"""User administration + last-active-admin lockout tests (§10.3, Phase 4
Slice 3)."""

from __future__ import annotations

import pytest
from app.models import AppUser, AuditEvent
from app.services.auth_service import hash_password, verify_password
from app.services.user_service import (
    LastAdminError,
    UserError,
    active_admin_count,
    create_user,
    list_users,
    set_active,
    update_role,
)
from sqlalchemy import select

pytestmark = pytest.mark.integration


def _user(session, *, email="u@x.local", role="analyst", active=True) -> AppUser:
    user = AppUser(
        email=email, display_name="U", password_hash=hash_password("whatever1"),
        role=role, is_active=active,
    )
    session.add(user)
    session.flush()
    return user


# ---- create_user ----


def test_create_user_success(db_session) -> None:
    user = create_user(
        db_session, email="New@Example.com", display_name="New Person",
        role="analyst", password="a-long-password",
    )
    assert user.email == "new@example.com"  # normalized
    assert user.is_active is True
    assert verify_password(user.password_hash, "a-long-password") is True


def test_create_user_writes_audit_event(db_session) -> None:
    user = create_user(
        db_session, email="a@x.local", display_name="A", role="admin",
        password="a-long-password", actor_id=None,
    )
    events = db_session.scalars(select(AuditEvent).where(AuditEvent.action == "user_created")).all()
    assert len(events) == 1
    assert events[0].target == f"app_user:{user.id}"
    assert events[0].event_metadata["role"] == "admin"


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"email": "  ", "display_name": "X", "role": "analyst", "password": "longenough"}, "Email is required"),
        ({"email": "x@y.z", "display_name": " ", "role": "analyst", "password": "longenough"}, "Display name is required"),
        ({"email": "x@y.z", "display_name": "X", "role": "superuser", "password": "longenough"}, "Invalid role"),
        ({"email": "x@y.z", "display_name": "X", "role": "analyst", "password": "short"}, "at least 8 characters"),
    ],
)
def test_create_user_validation(db_session, kwargs, match) -> None:
    with pytest.raises(UserError, match=match):
        create_user(db_session, **kwargs)


def test_create_user_duplicate_email_rejected(db_session) -> None:
    _user(db_session, email="dupe@x.local")
    with pytest.raises(UserError, match="already exists"):
        create_user(
            db_session, email="dupe@x.local", display_name="Other",
            role="analyst", password="a-long-password",
        )


def test_list_users_ordered_by_creation(db_session) -> None:
    a = _user(db_session, email="a@x.local")
    b = _user(db_session, email="b@x.local")
    rows = list_users(db_session)
    assert [r.id for r in rows] == [a.id, b.id]


# ---- last-active-admin lockout: deactivate path ----


def test_deactivate_non_last_admin_succeeds(db_session) -> None:
    _user(db_session, email="admin1@x.local", role="admin")
    admin2 = _user(db_session, email="admin2@x.local", role="admin")
    set_active(db_session, admin2.id, False)
    assert admin2.is_active is False


def test_deactivate_last_active_admin_blocked(db_session) -> None:
    only_admin = _user(db_session, email="admin@x.local", role="admin")
    with pytest.raises(LastAdminError, match="last active admin"):
        set_active(db_session, only_admin.id, False)
    assert only_admin.is_active is True  # unchanged


def test_deactivate_last_admin_still_blocked_with_other_inactive_admins(db_session) -> None:
    """A deactivated admin doesn't count toward the floor — only ACTIVE
    admins do."""
    active_admin = _user(db_session, email="admin1@x.local", role="admin", active=True)
    _user(db_session, email="admin2@x.local", role="admin", active=False)
    with pytest.raises(LastAdminError):
        set_active(db_session, active_admin.id, False)


def test_deactivate_non_admin_never_blocked_regardless_of_admin_count(db_session) -> None:
    only_admin = _user(db_session, email="admin@x.local", role="admin")
    analyst = _user(db_session, email="analyst@x.local", role="analyst")
    set_active(db_session, analyst.id, False)  # must not raise
    assert analyst.is_active is False
    assert only_admin.is_active is True


def test_deactivating_an_already_inactive_user_is_a_harmless_no_op(db_session) -> None:
    """Re-deactivating an already-inactive admin must not trip the lockout —
    they aren't propping up the active-admin floor in the first place."""
    _user(db_session, email="admin1@x.local", role="admin")  # the one active admin
    admin2 = _user(db_session, email="admin2@x.local", role="admin", active=False)
    set_active(db_session, admin2.id, False)  # already inactive — must not raise
    assert admin2.is_active is False


# ---- last-active-admin lockout: demote path ----


def test_demote_non_last_admin_succeeds(db_session) -> None:
    _user(db_session, email="admin1@x.local", role="admin")
    admin2 = _user(db_session, email="admin2@x.local", role="admin")
    update_role(db_session, admin2.id, "analyst")
    assert admin2.role == "analyst"


def test_demote_last_active_admin_blocked(db_session) -> None:
    only_admin = _user(db_session, email="admin@x.local", role="admin")
    with pytest.raises(LastAdminError, match="last active admin"):
        update_role(db_session, only_admin.id, "read_only")
    assert only_admin.role == "admin"  # unchanged


def test_demote_last_admin_to_admin_noop_never_blocked(db_session) -> None:
    """Setting the same role ('admin' -> 'admin') is not a demotion and must
    never trip the lockout, even for the sole admin."""
    only_admin = _user(db_session, email="admin@x.local", role="admin")
    update_role(db_session, only_admin.id, "admin")  # must not raise
    assert only_admin.role == "admin"


def test_promoting_someone_to_admin_never_blocked(db_session) -> None:
    _user(db_session, email="admin@x.local", role="admin")
    analyst = _user(db_session, email="analyst@x.local", role="analyst")
    update_role(db_session, analyst.id, "admin")  # increases admin count — never blocked
    assert analyst.role == "admin"


def test_demoting_an_inactive_admin_never_blocked(db_session) -> None:
    """An inactive admin isn't propping up the floor in the first place, so
    demoting them can't newly violate it."""
    _user(db_session, email="admin1@x.local", role="admin")  # the one active admin
    inactive_admin = _user(db_session, email="admin2@x.local", role="admin", active=False)
    update_role(db_session, inactive_admin.id, "read_only")  # must not raise
    assert inactive_admin.role == "read_only"


def test_update_role_invalid_role_rejected(db_session) -> None:
    user = _user(db_session, email="u@x.local", role="analyst")
    with pytest.raises(UserError, match="Invalid role"):
        update_role(db_session, user.id, "superuser")


def test_update_role_writes_audit_event(db_session) -> None:
    _user(db_session, email="admin1@x.local", role="admin")
    user = _user(db_session, email="u@x.local", role="analyst")
    update_role(db_session, user.id, "admin", actor_id=None)
    events = db_session.scalars(select(AuditEvent).where(AuditEvent.action == "user_role_changed")).all()
    assert len(events) == 1
    assert events[0].event_metadata == {"from": "analyst", "to": "admin"}


# ---- active_admin_count ----


def test_active_admin_count(db_session) -> None:
    a = _user(db_session, email="a@x.local", role="admin", active=True)
    _user(db_session, email="b@x.local", role="admin", active=False)
    _user(db_session, email="c@x.local", role="analyst", active=True)
    assert active_admin_count(db_session) == 1
    assert active_admin_count(db_session, excluding=a.id) == 0
