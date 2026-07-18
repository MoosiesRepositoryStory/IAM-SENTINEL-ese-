"""Login / logout (§10.1, Phase 4 Slice 1).

Registers on the same ``bp`` as the rest of the app (see ``create_app()``) so
these are plain ``web.login`` / ``web.logout`` endpoints rather than a second
blueprint prefix. The login form is the one place in this app that carries a
CSRF token (Flask-WTF) — everything else relies on the session cookie's
SameSite=Lax policy (see ``create_app()``'s comment).
"""

from __future__ import annotations

from typing import cast

from flask import Response, redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField
from wtforms.validators import DataRequired, Email

from app.db import session_scope
from app.models import AuditEvent
from app.services.auth_service import DEMO_PASSWORD, DEMO_USERS, AuthError, authenticate
from app.web.views import bp


class LoginForm(FlaskForm):
    # check_deliverability=False: this is a syntax check, not a "does this
    # domain really exist" check — email-validator's default DNS lookup would
    # otherwise reject any real self-hosted deployment behind a private/
    # internal domain outright (see auth_service.py's DEMO_USERS comment for
    # the *other*, non-optional rejection this ran into with @demo.local).
    email = StringField("Email", validators=[DataRequired(), Email(check_deliverability=False)])
    password = PasswordField("Password", validators=[DataRequired()])


@bp.get("/login")
@bp.post("/login")
def login() -> Response | str:
    if current_user.is_authenticated:
        return cast(Response, redirect(url_for("web.index")))

    form = LoginForm()
    error: str | None = None
    if form.validate_on_submit():
        with session_scope() as session:
            try:
                user = authenticate(session, form.email.data or "", form.password.data or "")
                session.add(AuditEvent(actor_id=user.id, action="login", target=f"app_user:{user.id}"))
                session.flush()
                session.expunge(user)
            except AuthError as exc:
                error = str(exc)
                user = None
        if user is not None:
            login_user(user)
            dest = request.args.get("next")
            # Never redirect off-site with an attacker-supplied `next` — only
            # accept a same-app relative path.
            if not dest or not dest.startswith("/") or dest.startswith("//"):
                dest = url_for("web.index")
            return cast(Response, redirect(dest))
    elif request.method == "POST":
        # Covers malformed field input AND a missing/invalid CSRF token with
        # the same generic message as a wrong password (§10.1's "don't leak
        # which specific check failed" posture) — none of these ever reach
        # authenticate(), so no session is created either way.
        error = "Invalid email or password."

    return render_template(
        "login.html", form=form, error=error, demo_users=DEMO_USERS, demo_password=DEMO_PASSWORD
    )


@bp.post("/logout")
def logout() -> Response:
    # No @login_required here: bp.before_request's _require_login() already
    # gates every non-public route on this blueprint (including this one)
    # before the view runs, so a second guard would be dead code, not defense
    # in depth.
    with session_scope() as session:
        session.add(
            AuditEvent(actor_id=current_user.id, action="logout", target=f"app_user:{current_user.id}")
        )
    logout_user()
    if request.headers.get("HX-Request") == "true":
        resp = Response(status=200)
        resp.headers["HX-Redirect"] = url_for("web.login")
        return resp
    return cast(Response, redirect(url_for("web.login")))
