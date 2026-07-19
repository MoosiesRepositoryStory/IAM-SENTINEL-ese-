"""Authentication (§10.1, Phase 4 Slice 1): password hashing, login
verification, and the seeded demo roster.

Role *enforcement* (§10.2) is deliberately not here — this slice is the
mechanism (who are you), not the policy (what can you do), which lands in
Slice 2 alongside the route/service guards it protects.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AppUser
from app.models.base import now_iso

_hasher = PasswordHasher()

# Shown on the login page so a recruiter can sign in instantly (§10.1). One
# shared password across all three seeded accounts — a portfolio-demo
# convenience, not a real credential; there is nothing behind it worth
# protecting beyond the demo data itself.
DEMO_PASSWORD = "iam-sentinel-demo"

# (email, display_name, role) — seeded idempotently on every app boot.
#
# Domain note: the spec's own suggestion (§10.1) was @demo.local, but
# `.local` is an IANA/RFC 2606 special-use reserved name that the
# email-validator library hard-rejects as a syntax error, independent of its
# deliverability (DNS) check — there's no flag to opt back into it. example.com
# is the closest equivalent that's both obviously-not-a-real-address *and*
# passes validation (it's RFC 2606's own reserved-for-documentation domain).
DEMO_USERS: tuple[tuple[str, str, str], ...] = (
    ("admin@example.com", "Demo Admin", "admin"),
    ("analyst@example.com", "Demo Analyst", "analyst"),
    ("viewer@example.com", "Demo Viewer", "read_only"),
)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


class AuthError(ValueError):
    """Raised by :func:`authenticate` on any failure. The message is
    deliberately the same generic text for every failure mode (unknown email,
    wrong password, deactivated account) so the login form can't be used to
    enumerate registered emails."""


def authenticate(session: Session, email: str, password: str) -> AppUser:
    """Verify credentials and return the user, updating ``last_login_at``.
    Raises :class:`AuthError` for any unknown email, wrong password, or
    deactivated account — all with the same message (see above)."""
    user = session.scalar(select(AppUser).where(AppUser.email == email.strip().lower()))
    if user is None or not user.is_active or not verify_password(user.password_hash, password):
        raise AuthError("Invalid email or password.")
    user.last_login_at = now_iso()
    session.flush()
    return user


def change_password(session: Session, user: AppUser, current_password: str, new_password: str) -> None:
    """Self-service password change (§10.3, Phase 4 Slice 3) — any
    authenticated user, not just admins; requires the current password so a
    hijacked/left-open session can't silently lock out the real owner.
    Unlike :func:`authenticate`, the error messages here are specific (which
    field was wrong) — there's no enumeration risk once the caller is already
    an authenticated, identified session."""
    if not verify_password(user.password_hash, current_password):
        raise AuthError("Current password is incorrect.")
    if not new_password or len(new_password) < 8:
        raise AuthError("New password must be at least 8 characters.")
    user.password_hash = hash_password(new_password)
    session.flush()


def seed_demo_users(session: Session) -> None:
    """Idempotently ensure the three demo accounts exist. Safe to call on
    every app boot (``create_app()``) — an existing row (matched by email) is
    left untouched, including any password an admin has since changed."""
    for email, display_name, role in DEMO_USERS:
        if session.scalar(select(AppUser.id).where(AppUser.email == email)) is not None:
            continue
        session.add(
            AppUser(
                email=email,
                display_name=display_name,
                password_hash=hash_password(DEMO_PASSWORD),
                role=role,
                is_active=True,
            )
        )
    session.flush()
