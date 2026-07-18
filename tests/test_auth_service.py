"""Password hashing + authentication tests (§10.1, Phase 4 Slice 1)."""

from __future__ import annotations

import pytest
from app.models import AppUser
from app.services.auth_service import (
    DEMO_PASSWORD,
    DEMO_USERS,
    AuthError,
    authenticate,
    hash_password,
    seed_demo_users,
    verify_password,
)

pytestmark = pytest.mark.integration


def test_hash_roundtrip() -> None:
    h = hash_password("correct horse battery staple")
    assert h != "correct horse battery staple"  # never stored in plaintext
    assert verify_password(h, "correct horse battery staple") is True


def test_wrong_password_fails_verification() -> None:
    h = hash_password("correct horse battery staple")
    assert verify_password(h, "wrong password") is False


def _make_user(session, *, email="u@x.local", password="s3cret-pw", active=True) -> AppUser:
    user = AppUser(
        email=email,
        display_name="U",
        password_hash=hash_password(password),
        role="analyst",
        is_active=active,
    )
    session.add(user)
    session.flush()
    return user


def test_authenticate_success_updates_last_login(db_session) -> None:
    user = _make_user(db_session, password="s3cret-pw")
    assert user.last_login_at is None

    logged_in = authenticate(db_session, "u@x.local", "s3cret-pw")
    assert logged_in.id == user.id
    assert logged_in.last_login_at is not None


def test_authenticate_wrong_password_raises(db_session) -> None:
    _make_user(db_session, password="s3cret-pw")
    with pytest.raises(AuthError):
        authenticate(db_session, "u@x.local", "not-the-password")


def test_authenticate_unknown_email_raises_same_error(db_session) -> None:
    """Same exception type/message for unknown-email and wrong-password —
    the login form must not be able to enumerate registered emails."""
    _make_user(db_session, password="s3cret-pw")
    unknown_msg = None
    wrong_pw_msg = None
    try:
        authenticate(db_session, "nobody@x.local", "whatever")
    except AuthError as exc:
        unknown_msg = str(exc)
    try:
        authenticate(db_session, "u@x.local", "wrong")
    except AuthError as exc:
        wrong_pw_msg = str(exc)
    assert unknown_msg == wrong_pw_msg


def test_authenticate_deactivated_user_raises(db_session) -> None:
    _make_user(db_session, password="s3cret-pw", active=False)
    with pytest.raises(AuthError):
        authenticate(db_session, "u@x.local", "s3cret-pw")


def test_email_matching_is_case_and_whitespace_insensitive(db_session) -> None:
    session = db_session
    session.add(
        AppUser(
            email="lower@x.local",
            display_name="U",
            password_hash=hash_password("pw"),
            role="analyst",
        )
    )
    session.flush()
    user = authenticate(session, "  LOWER@x.local  ", "pw")
    assert user.email == "lower@x.local"


def test_seed_demo_users_creates_all_three(db_session) -> None:
    seed_demo_users(db_session)
    from sqlalchemy import select

    rows = db_session.scalars(select(AppUser)).all()
    assert {r.email for r in rows} == {e for e, _, _ in DEMO_USERS}
    assert {r.role for r in rows} == {"admin", "analyst", "read_only"}
    for email, _, _ in DEMO_USERS:
        user = authenticate(db_session, email, DEMO_PASSWORD)
        assert user.email == email


def test_seed_demo_users_is_idempotent_and_preserves_changes(db_session) -> None:
    """A second seed call must not duplicate rows or clobber an admin's
    subsequent changes (e.g. a rotated password or a deactivated account)."""
    from sqlalchemy import func, select

    seed_demo_users(db_session)
    admin = db_session.scalar(select(AppUser).where(AppUser.email == "admin@example.com"))
    admin.password_hash = hash_password("rotated-by-admin")
    admin.is_active = False
    db_session.flush()

    seed_demo_users(db_session)  # must be a no-op for existing rows

    count = db_session.scalar(select(func.count()).select_from(AppUser))
    assert count == 3
    reloaded = db_session.scalar(select(AppUser).where(AppUser.email == "admin@example.com"))
    assert reloaded.is_active is False
    assert verify_password(reloaded.password_hash, "rotated-by-admin") is True
