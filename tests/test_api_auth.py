"""JWT bearer-token auth tests for /api/v1 (§10.4, Phase 4 Slice 4a): token
issuance, expiry, and invalid-token rejection, plus the deactivated-user path
that mirrors the HTML app's own Slice 3 fix (a token stays cryptographically
valid but the account behind it is re-checked fresh on every request).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from app.api.auth import ALGORITHM, create_token
from app.services.auth_service import DEMO_PASSWORD
from app.services.user_service import set_active

pytestmark = pytest.mark.integration


def _login(client, email: str, password: str):  # noqa: ANN001
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


# ---- token issuance ---------------------------------------------------------


def test_login_issues_a_bearer_token(client) -> None:
    resp = _login(client, "admin@example.com", DEMO_PASSWORD)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["token_type"] == "Bearer"
    assert body["user"] == {
        "id": 1,
        "email": "admin@example.com",
        "display_name": "Demo Admin",
        "role": "admin",
    }
    # A real, decodable JWT carrying the documented claims.
    payload = jwt.decode(body["token"], options={"verify_signature": False})
    assert payload["user_id"] == 1
    assert payload["role"] == "admin"
    assert "exp" in payload and "iat" in payload


def test_token_expiry_is_approximately_12_hours(client) -> None:
    resp = _login(client, "admin@example.com", DEMO_PASSWORD)
    payload = jwt.decode(resp.get_json()["token"], options={"verify_signature": False})
    ttl = payload["exp"] - payload["iat"]
    assert ttl == timedelta(hours=12).total_seconds()


def test_login_wrong_password_rejected_with_envelope(client) -> None:
    resp = _login(client, "admin@example.com", "not-the-password")
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "invalid_credentials"


def test_login_unknown_email_same_generic_message_as_wrong_password(client) -> None:
    """Same anti-enumeration property as the HTML login (§10.1)."""
    wrong_pw = _login(client, "admin@example.com", "nope").get_json()["error"]["message"]
    unknown = _login(client, "nobody@example.com", "nope").get_json()["error"]["message"]
    assert wrong_pw == unknown


def test_login_deactivated_user_rejected(client, db_session) -> None:
    from app.models import AppUser
    from sqlalchemy import select

    analyst_id = db_session.scalar(select(AppUser.id).where(AppUser.email == "analyst@example.com"))
    set_active(db_session, analyst_id, False)
    db_session.commit()

    resp = _login(client, "analyst@example.com", DEMO_PASSWORD)
    assert resp.status_code == 401


def test_login_validation_error_uses_the_error_envelope(client) -> None:
    resp = client.post("/api/v1/auth/login", json={"email": "not-an-email", "password": "x"})
    assert resp.status_code == 422
    body = resp.get_json()
    assert "error" in body and "code" in body["error"] and "message" in body["error"]


# ---- bearer-token verification ---------------------------------------------


def test_no_authorization_header_rejected(client) -> None:
    resp = client.get("/api/v1/me")
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "unauthorized"


def test_malformed_authorization_header_rejected(client) -> None:
    resp = client.get("/api/v1/me", headers={"Authorization": "not-a-bearer-token"})
    assert resp.status_code == 401


def test_garbage_token_rejected(client) -> None:
    resp = client.get("/api/v1/me", headers={"Authorization": "Bearer garbage.not.a.jwt"})
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "invalid_token"


def test_token_signed_with_wrong_key_rejected(client) -> None:
    now = datetime.now(UTC)
    bad_token = jwt.encode(
        {
            "user_id": 1,
            "role": "admin",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
        },
        "wrong-secret-key",
        algorithm=ALGORITHM,
    )
    resp = client.get("/api/v1/me", headers={"Authorization": f"Bearer {bad_token}"})
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "invalid_token"


def test_expired_token_rejected(client) -> None:
    with client.application.app_context():
        from flask import current_app

        secret = current_app.config["JWT_SECRET_KEY"]
    now = datetime.now(UTC)
    expired = jwt.encode(
        {
            "user_id": 1,
            "role": "admin",
            "iat": int((now - timedelta(hours=13)).timestamp()),
            "exp": int((now - timedelta(hours=1)).timestamp()),
        },
        secret,
        algorithm=ALGORITHM,
    )
    resp = client.get("/api/v1/me", headers={"Authorization": f"Bearer {expired}"})
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "token_expired"


def test_valid_token_grants_access(client) -> None:
    token = _login(client, "admin@example.com", DEMO_PASSWORD).get_json()["token"]
    resp = client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.get_json()["email"] == "admin@example.com"


def test_token_stops_working_the_request_after_the_user_is_deactivated(client, db_session) -> None:
    """Mirrors the HTML app's Slice 3 fix (user_loader re-checking is_active)
    — a still-unexpired, cryptographically valid token must stop granting
    access the moment the account behind it is deactivated, not linger until
    the token's own ~12h expiry."""
    from app.models import AppUser
    from sqlalchemy import select

    token = _login(client, "analyst@example.com", DEMO_PASSWORD).get_json()["token"]
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200

    analyst_id = db_session.scalar(select(AppUser.id).where(AppUser.email == "analyst@example.com"))
    set_active(db_session, analyst_id, False)
    db_session.commit()

    resp = client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_create_token_helper_returns_a_decodable_token() -> None:
    """Unit-level smoke test for the pure helper, independent of the Flask
    request cycle covered above."""
    from app.models import AppUser

    user = AppUser(id=42, email="x@y.z", display_name="X", password_hash="!", role="analyst")
    token, expires_at = create_token(user, "some-secret")
    payload = jwt.decode(token, "some-secret", algorithms=[ALGORITHM])
    assert payload["user_id"] == 42
    assert payload["role"] == "analyst"
    assert payload["exp"] == int(expires_at.timestamp())
