"""Settings shell + user administration + self-service profile (§10.3,
Phase 4 Slice 3). Registers on the same ``bp`` as views.py/auth_views.py —
see auth_views.py's docstring for why (keeps everything on one blueprint so
a future /api/v1 blueprint's separate JWT auth doesn't get accidentally
session-gated by this one). Every route here already sits behind the
blueprint's login gate (``bp.before_request`` in views.py); ``/settings/users/*``
additionally requires ``Capability.MANAGE_USERS`` (admin) via the same
``require_role`` decorator Slice 2 established.
"""

from __future__ import annotations

from typing import cast

from flask import Response, abort, redirect, render_template, request, url_for
from flask_login import current_user

from app.db import session_scope
from app.models import AppUser
from app.services.auth_service import AuthError, change_password
from app.services.rbac import ROLES, Capability
from app.services.user_service import (
    LastAdminError,
    UserError,
    active_admin_count,
    create_user,
    list_users,
    set_active,
    update_role,
)
from app.web.authz import require_role
from app.web.views import bp


@bp.get("/settings")
def settings_index() -> str:
    return render_template("settings.html")


def _users_page(*, error: str | None = None, form_open: bool = False, status: int = 200):  # noqa: ANN201
    with session_scope() as session:
        users = list_users(session)
        # Drives the "can't touch the last admin" disabling of that one row's
        # controls (see settings_users.html) — a UX hint, not the actual
        # guard (user_service re-checks server-side regardless).
        lockout_id = next(
            (u.id for u in users if u.role == "admin" and u.is_active and active_admin_count(session, excluding=u.id) == 0),
            None,
        )
        for u in users:
            session.expunge(u)
    body = render_template(
        "settings_users.html", users=users, roles=ROLES, error=error, form_open=form_open,
        lockout_id=lockout_id,
    )
    return (body, status) if status != 200 else body


@bp.get("/settings/users")
@require_role(Capability.MANAGE_USERS)
def users_admin() -> str:
    return _users_page()


@bp.post("/settings/users")
@require_role(Capability.MANAGE_USERS)
def users_create() -> Response | str | tuple[str, int]:
    with session_scope() as session:
        try:
            create_user(
                session,
                email=request.form.get("email", ""),
                display_name=request.form.get("display_name", ""),
                role=request.form.get("role", "read_only"),
                password=request.form.get("password", ""),
                actor_id=current_user.id,
            )
        except UserError as exc:
            return _users_page(error=str(exc), form_open=True, status=400)
    return cast(Response, redirect(url_for("web.users_admin")))


@bp.post("/settings/users/<int:user_id>/role")
@require_role(Capability.MANAGE_USERS)
def users_update_role(user_id: int) -> Response | str | tuple[str, int]:
    new_role = request.form.get("role", "")
    with session_scope() as session:
        try:
            update_role(session, user_id, new_role, actor_id=current_user.id)
        except (UserError, LastAdminError) as exc:
            return _users_page(error=str(exc), status=400)
    return cast(Response, redirect(url_for("web.users_admin")))


@bp.post("/settings/users/<int:user_id>/active")
@require_role(Capability.MANAGE_USERS)
def users_toggle_active(user_id: int) -> Response | str | tuple[str, int]:
    is_active = request.form.get("is_active") == "1"
    with session_scope() as session:
        try:
            set_active(session, user_id, is_active, actor_id=current_user.id)
        except (UserError, LastAdminError) as exc:
            return _users_page(error=str(exc), status=400)
    return cast(Response, redirect(url_for("web.users_admin")))


# -- Self-service profile (§10.3): any authenticated user, own account only --


@bp.get("/profile")
def profile() -> str:
    return render_template("profile.html")


@bp.post("/profile/password")
def profile_change_password() -> Response | str | tuple[str, int]:
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    if new_password != confirm_password:
        return render_template("profile.html", error="New password and confirmation do not match."), 400
    with session_scope() as session:
        user = session.get(AppUser, current_user.id)
        if user is None:
            abort(404)
        try:
            change_password(session, user, current_password, new_password)
        except AuthError as exc:
            return render_template("profile.html", error=str(exc)), 400
    return render_template("profile.html", success=True)
