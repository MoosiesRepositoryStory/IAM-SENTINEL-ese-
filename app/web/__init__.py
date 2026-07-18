"""Flask application factory.

Phase 1 grows the web surface into the blueprinted UX shell: sidebar/topbar,
theme tokens, and the findings table (§8.2). Templates live in ``templates/`` and
static assets (vendored htmx + Alpine, CSS) in ``static/``.
"""

from __future__ import annotations

from flask import Flask
from flask_login import LoginManager

from app.config import get_settings
from app.db import init_engine, session_scope
from app.models import AppUser
from app.scheduler import start_scheduler
from app.services.auth_service import seed_demo_users

login_manager = LoginManager()
login_manager.login_view = "web.login"


@login_manager.user_loader
def _load_user(user_id: str) -> AppUser | None:
    # Loaded in its own short-lived session and returned detached (the app's
    # established pattern — see views.py's expunge discipline): AppUser has no
    # relationships, so its already-loaded scalar columns (id/email/role/...)
    # stay safely readable as `current_user` for the rest of the request.
    with session_scope() as session:
        return session.get(AppUser, int(user_id))


def create_app(*, start_background_jobs: bool = True) -> Flask:
    """``start_background_jobs=False`` skips ``start_scheduler()`` — used by
    the test client fixture, since APScheduler's start is a process-wide
    singleton (§ scheduler.py) that would otherwise keep pointing at a prior
    test's already-torn-down engine across repeated ``create_app()`` calls."""
    app = Flask(__name__, template_folder="templates", static_folder="static")
    settings = get_settings()
    app.config["SECRET_KEY"] = settings.secret_key
    # Session cookie hardening (§10.1): SameSite=Lax is this app's CSRF
    # mitigation for the many htmx mutating POSTs, which carry no per-request
    # token (only the login form does, via Flask-WTF) — a cross-site request
    # can't carry a Lax-scoped cookie on a simple POST, so those routes stay
    # safe without threading a token through every htmx form.
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    init_engine(settings)
    login_manager.init_app(app)

    from app.web import auth_views  # noqa: F401 — registers /login, /logout on `bp`
    from app.web.views import bp

    app.register_blueprint(bp)

    with session_scope() as session:
        seed_demo_users(session)

    # Recurring scans + the daily exception-expiry job (§5.5 / §11.4, Slice 5).
    # start_scheduler() is idempotent, so this is safe even if create_app() is
    # ever called more than once in a process. Not called from anywhere in the
    # CLI (app/cli.py never imports create_app), so `iam-sentinel scan` stays a
    # one-shot command with no background thread — only the web app runs one.
    if start_background_jobs:
        start_scheduler()

    return app
