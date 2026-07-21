"""Login/logout route + login-gate tests (§10.1, Phase 4 Slice 1).

Uses the ``client`` fixture (a real Flask test client against a throwaway DB,
CSRF disabled for convenience — see conftest.py). The one CSRF-specific test
builds its own app with CSRF left on.
"""

from __future__ import annotations

import pytest
from app.services.auth_service import DEMO_PASSWORD

pytestmark = pytest.mark.integration


def _login(client, email: str, password: str):  # noqa: ANN001
    return client.post(
        "/login", data={"email": email, "password": password}, follow_redirects=False
    )


# --- unauthenticated access ---------------------------------------------------


def test_unauthenticated_root_redirects_to_login(client) -> None:
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert (
        resp.headers["Location"].endswith("/login?next=%2F") or "/login" in resp.headers["Location"]
    )


def test_unauthenticated_htmx_request_gets_hx_redirect_not_a_302(client) -> None:
    """An htmx fetch can't usefully follow a normal redirect into a full HTML
    page inside its swap target — it needs the HX-Redirect header instead."""
    resp = client.get("/findings", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    assert resp.headers.get("HX-Redirect") == "/login"


def test_login_page_itself_is_public(client) -> None:
    assert client.get("/login").status_code == 200


def test_healthz_is_public(client) -> None:
    assert client.get("/healthz").status_code == 200


# --- login success/failure ----------------------------------------------------


def test_login_with_demo_admin_succeeds_and_grants_access(client) -> None:
    resp = _login(client, "admin@example.com", DEMO_PASSWORD)
    assert resp.status_code == 302
    assert "/login" not in resp.headers["Location"]

    # The session cookie now grants access to a previously-gated route.
    resp2 = client.get("/", follow_redirects=False)
    assert resp2.status_code == 200


def test_login_wrong_password_shows_generic_error_and_stays_logged_out(client) -> None:
    resp = _login(client, "admin@example.com", "not-the-password")
    assert resp.status_code == 200  # re-renders the form, no redirect
    assert b"Invalid email or password" in resp.data

    still_gated = client.get("/", follow_redirects=False)
    assert still_gated.status_code == 302


def test_login_unknown_email_shows_the_same_generic_error(client) -> None:
    resp = _login(client, "nobody@example.com", "whatever")
    assert b"Invalid email or password" in resp.data


@pytest.mark.parametrize(
    ("email", "role"),
    [
        ("admin@example.com", "admin"),
        ("analyst@example.com", "analyst"),
        ("viewer@example.com", "read_only"),
    ],
)
def test_all_three_seeded_demo_users_can_log_in(client, email, role) -> None:
    resp = _login(client, email, DEMO_PASSWORD)
    assert resp.status_code == 302
    assert "/login" not in resp.headers["Location"]


# --- next= redirect safety ----------------------------------------------------


def test_next_redirect_goes_to_the_requested_page(client) -> None:
    resp = client.post(
        "/login?next=/runs",
        data={"email": "admin@example.com", "password": DEMO_PASSWORD},
        follow_redirects=False,
    )
    assert resp.headers["Location"] == "/runs"


def test_next_redirect_rejects_an_offsite_url(client) -> None:
    """A `next=` pointing off-app (or protocol-relative //evil.com) must not
    be honored — this is exactly the open-redirect class of bug. Falls back
    to url_for("web.index"), which resolves to one of its two equivalent
    routes ("/" or "/dashboard" both serve the same view) — either is a safe,
    correct fallback, so accept both rather than assuming which one Werkzeug
    picks as canonical."""
    resp = client.post(
        "/login?next=https://evil.example/phish",
        data={"email": "admin@example.com", "password": DEMO_PASSWORD},
        follow_redirects=False,
    )
    assert resp.headers["Location"] in {"/", "/dashboard"}

    resp2 = client.post(
        "/login?next=//evil.example/phish",
        data={"email": "admin@example.com", "password": DEMO_PASSWORD},
        follow_redirects=False,
    )
    assert resp2.headers["Location"] in {"/", "/dashboard"}


# --- logout --------------------------------------------------------------------


def test_logout_clears_the_session_and_regates_access(client) -> None:
    _login(client, "admin@example.com", DEMO_PASSWORD)
    assert client.get("/").status_code == 200

    resp = client.post("/logout", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]

    assert client.get("/", follow_redirects=False).status_code == 302


def test_already_authenticated_visiting_login_redirects_to_dashboard(client) -> None:
    _login(client, "admin@example.com", DEMO_PASSWORD)
    resp = client.get("/login", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"] in {"/", "/dashboard"}


# --- CSRF (a dedicated app instance with protection left ON) ------------------


def test_login_form_rejects_a_post_without_a_csrf_token() -> None:
    """This app doesn't register Flask-WTF's global CSRFProtect (only the
    login form itself carries a token — see create_app()'s SameSite=Lax
    comment for why the rest of the app doesn't need one), so a missing token
    doesn't abort with 400; FlaskForm.validate_on_submit() just returns False,
    which is enough on its own: authenticate() is never called and no session
    is created. That's the actual security property to verify — a raw POST
    with correct credentials but no CSRF token must NOT log the caller in."""
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        os.environ["DATABASE_URL"] = f"sqlite:///{tmp}/csrf_test.db"
        os.environ["DATA_DIR"] = tmp
        from app import db as db_module

        db_module.reset_engine()
        db_module.create_all()
        try:
            from app.web import create_app

            app = create_app(start_background_jobs=False)
            app.config.update(TESTING=True)  # WTF_CSRF_ENABLED left at its True default
            with app.test_client() as c:
                resp = c.post(
                    "/login",
                    data={"email": "admin@example.com", "password": DEMO_PASSWORD},
                    follow_redirects=False,
                )
                assert resp.status_code == 200  # re-rendered the form, not a redirect
                assert b"Invalid email or password" in resp.data

                # The decisive check: no session was created despite correct
                # credentials, because the CSRF-less form never validated.
                still_gated = c.get("/", follow_redirects=False)
                assert still_gated.status_code == 302
        finally:
            db_module.reset_engine()
            os.environ.pop("DATABASE_URL", None)
            os.environ.pop("DATA_DIR", None)
