"""Settings + create_app() canonical-URL configuration tests (§10.4-adjacent
hardening: a Host-header-derived external link is a link-poisoning risk for
anything sent to an external integration — see views.finding_create_ticket /
api.findings' finding_url)."""

from __future__ import annotations

from app.config import Settings


def test_public_base_url_defaults_to_none(monkeypatch) -> None:
    monkeypatch.delenv("PUBLIC_BASE_URL", raising=False)
    assert Settings.from_env().public_base_url is None


def test_public_base_url_read_from_env(monkeypatch) -> None:
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://sentinel.example.com")
    assert Settings.from_env().public_base_url == "https://sentinel.example.com"


def test_create_app_pins_server_name_when_public_base_url_set(db_session, monkeypatch) -> None:
    """PUBLIC_BASE_URL, when set, pins SERVER_NAME/PREFERRED_URL_SCHEME so an
    externally-generated link can't be steered by a spoofed Host header."""
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://sentinel.example.com")
    from app.web import create_app

    app = create_app(start_background_jobs=False)
    assert app.config["SERVER_NAME"] == "sentinel.example.com"
    assert app.config["PREFERRED_URL_SCHEME"] == "https"

    from flask import url_for

    # A request arrives over the app's real TLS termination (https, as any
    # internet-facing deployment would be) but claiming a spoofed Host header;
    # the generated external URL's *domain* must still be the canonical
    # configured one, not the attacker-controlled Host — that's the actual
    # link-poisoning vector this fix closes. (The scheme, by contrast, is
    # legitimately taken from the real request when one is active — Werkzeug
    # only falls back to PREFERRED_URL_SCHEME outside a request context, e.g.
    # a background job building a link with no request at all.)
    with app.test_request_context("/findings/1", base_url="https://attacker.example.com"):
        url = url_for("web.finding_drawer", group_id=1, _external=True)
    assert url.startswith("https://sentinel.example.com/")
    assert "attacker" not in url

    with app.app_context():
        # No active request at all (the scenario PREFERRED_URL_SCHEME exists
        # for) — still resolves to the canonical host and scheme.
        url = url_for("web.finding_drawer", group_id=1, _external=True)
    assert url == "https://sentinel.example.com/findings/1"


def test_create_app_leaves_server_name_unset_by_default(db_session, monkeypatch) -> None:
    """Unset PUBLIC_BASE_URL (the dev/demo default) keeps Flask's normal
    behavior of deriving external URLs from the incoming request."""
    monkeypatch.delenv("PUBLIC_BASE_URL", raising=False)
    from app.web import create_app

    app = create_app(start_background_jobs=False)
    assert app.config.get("SERVER_NAME") is None
