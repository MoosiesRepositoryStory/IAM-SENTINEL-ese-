"""User administration (§10.3, Phase 4 Slice 3): list/create/role-change and
activate/deactivate for the global user roster.

Gating is entirely route-level (``require_role(Capability.MANAGE_USERS)`` in
``app.web.settings_views``) — unlike Slice 2's ``connect_account``/
``create_exception``, MANAGE_USERS carries no internal role split (it's
uniformly admin-only), so there's nothing here that needs its own
``actor_role`` re-check on top of the route decorator (same posture as
``workflow_service.transition``/``collaboration.assign`` in Slice 2).

The one invariant this module DOES enforce unconditionally, independent of
who's asking, is the **last-active-admin lockout**: an action that would
leave the app with zero active admins (deactivating the last one, or
demoting it away from admin) is rejected outright. Without this the app
could permanently lock every human out of user administration — including
the admin who just made the mistake.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AppUser, AuditEvent
from app.services.auth_service import hash_password
from app.services.rbac import ROLES


class UserError(ValueError):
    """Bad input: unknown role, duplicate email, empty required field."""


class LastAdminError(ValueError):
    """Raised when an action would leave zero active admins."""


def list_users(session: Session) -> list[AppUser]:
    return list(session.scalars(select(AppUser).order_by(AppUser.created_at)))


def active_admin_count(session: Session, *, excluding: int | None = None) -> int:
    """Active admins right now, optionally excluding one user id — used both
    as the lockout check itself (``excluding`` the user about to be
    demoted/deactivated: would that leave zero?) and by the settings_users
    view to decide whether to disable that one row's controls."""
    stmt = select(func.count(AppUser.id)).where(AppUser.role == "admin", AppUser.is_active.is_(True))
    if excluding is not None:
        stmt = stmt.where(AppUser.id != excluding)
    return session.scalar(stmt) or 0


def create_user(
    session: Session,
    *,
    email: str,
    display_name: str,
    role: str,
    password: str,
    actor_id: int | None = None,
) -> AppUser:
    email = (email or "").strip().lower()
    display_name = (display_name or "").strip()
    if not email:
        raise UserError("Email is required.")
    if not display_name:
        raise UserError("Display name is required.")
    if role not in ROLES:
        raise UserError(f"Invalid role: {role!r}")
    if not password or len(password) < 8:
        raise UserError("Password must be at least 8 characters.")
    if session.scalar(select(AppUser.id).where(AppUser.email == email)) is not None:
        raise UserError("A user with that email already exists.")
    user = AppUser(
        email=email,
        display_name=display_name,
        role=role,
        password_hash=hash_password(password),
        is_active=True,
    )
    session.add(user)
    session.flush()
    session.add(
        AuditEvent(
            actor_id=actor_id,
            action="user_created",
            target=f"app_user:{user.id}",
            event_metadata={"email": email, "role": role},
        )
    )
    return user


def update_role(session: Session, user_id: int, new_role: str, *, actor_id: int | None = None) -> AppUser:
    if new_role not in ROLES:
        raise UserError(f"Invalid role: {new_role!r}")
    user = session.get(AppUser, user_id)
    if user is None:
        raise UserError("User not found.")
    # Only a currently-active admin actually counts toward the lockout floor
    # — demoting an already-deactivated admin, or a no-op "change" to the
    # same role, never reduces the number of admins who could act.
    if (
        user.role == "admin"
        and user.is_active
        and new_role != "admin"
        and active_admin_count(session, excluding=user.id) == 0
    ):
        raise LastAdminError("Cannot demote the last active admin.")
    old_role = user.role
    user.role = new_role
    session.flush()
    session.add(
        AuditEvent(
            actor_id=actor_id,
            action="user_role_changed",
            target=f"app_user:{user.id}",
            event_metadata={"from": old_role, "to": new_role},
        )
    )
    return user


def set_active(session: Session, user_id: int, is_active: bool, *, actor_id: int | None = None) -> AppUser:
    user = session.get(AppUser, user_id)
    if user is None:
        raise UserError("User not found.")
    if (
        not is_active
        and user.role == "admin"
        and user.is_active
        and active_admin_count(session, excluding=user.id) == 0
    ):
        raise LastAdminError("Cannot deactivate the last active admin.")
    user.is_active = is_active
    session.flush()
    session.add(
        AuditEvent(
            actor_id=actor_id,
            action="user_activated" if is_active else "user_deactivated",
            target=f"app_user:{user.id}",
        )
    )
    return user
