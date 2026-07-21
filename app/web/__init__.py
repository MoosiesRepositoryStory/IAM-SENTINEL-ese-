"""Flask application factory.

Phase 1 grows the web surface into the blueprinted UX shell: sidebar/topbar,
theme tokens, and the findings table (§8.2). Templates live in ``templates/`` and
static assets (vendored htmx + Alpine, CSS) in ``static/``.
"""

from __future__ import annotations

from urllib.parse import urlsplit

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
    #
    # Returning None for a deactivated user (§10.3, Phase 4 Slice 3) is
    # deliberate: Flask-Login's own UserMixin.is_active is just a property an
    # app can check wherever it likes — it does NOT, by itself, block an
    # already-established session. AppUser.is_active shadows it (a real mapped
    # column, found directly on the class), but without this check a user
    # deactivated mid-session would keep passing `current_user.is_authenticated`
    # in the blueprint's before_request gate and stay logged in regardless.
    # Returning None here makes user_loader itself the enforcement point: the
    # very next request re-derives "authenticated" as false, which is what
    # makes "Deactivate" in /settings/users actually take effect immediately
    # rather than merely blocking future logins (authenticate() already did
    # that half, since Phase 4 Slice 1).
    with session_scope() as session:
        user = session.get(AppUser, int(user_id))
        return user if user is not None and user.is_active else None


def create_app(*, start_background_jobs: bool = True) -> Flask:
    """``start_background_jobs=False`` skips ``start_scheduler()`` — used by
    the test client fixture, since APScheduler's start is a process-wide
    singleton (§ scheduler.py) that would otherwise keep pointing at a prior
    test's already-torn-down engine across repeated ``create_app()`` calls."""
    app = Flask(__name__, template_folder="templates", static_folder="static")
    settings = get_settings()
    settings.validate()  # fail closed on insecure defaults when ENVIRONMENT=production
    app.config["SECRET_KEY"] = settings.secret_key
    # Independent signing key for /api/v1's JWTs (app/api/auth.py) — see
    # Settings.jwt_secret_key's docstring for why this is deliberately not
    # just SECRET_KEY again.
    app.config["JWT_SECRET_KEY"] = settings.jwt_secret_key
    # Session cookie hardening (§10.1): SameSite=Lax is this app's CSRF
    # mitigation for the many htmx mutating POSTs, which carry no per-request
    # token (only the login form does, via Flask-WTF) — a cross-site request
    # can't carry a Lax-scoped cookie on a simple POST, so those routes stay
    # safe without threading a token through every htmx form.
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    # Cap request bodies at 8 MB. The only sizeable input is the Connect
    # wizard's inventory/policies/logs upload, which views._uploaded_text()
    # reads fully into memory — legitimate ones are tiny (KBs). Without a cap,
    # the shared-admin public demo (PUBLIC_MODE off, so any visitor with the
    # published demo password can reach the upload) could POST a multi-GB body
    # and OOM the small free-tier instance. Flask returns 413 past this.
    app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
    # Canonical host, when configured (PUBLIC_BASE_URL): pins SERVER_NAME /
    # PREFERRED_URL_SCHEME so url_for(_external=True) — used for the
    # ticket-notification deep link sent to external integrations, see
    # views.finding_create_ticket / api.findings — can't be poisoned by a
    # spoofed Host header. Unset (the dev/demo default) leaves Flask's normal
    # behavior of deriving external URLs from the incoming request's Host.
    if settings.public_base_url:
        parsed = urlsplit(settings.public_base_url)
        app.config["SERVER_NAME"] = parsed.netloc
        app.config["PREFERRED_URL_SCHEME"] = parsed.scheme or "https"
    init_engine(settings)
    login_manager.init_app(app)

    from app.web import (
        auth_views,  # noqa: F401 — registers /login, /logout on `bp`
        settings_views,  # noqa: F401 — registers /settings, /profile on `bp`
    )
    from app.web.views import bp

    app.register_blueprint(bp)

    # /api/v1 (Phase 4 Slice 4a, §10.4): a separate flask-smorest blueprint
    # tree on the SAME app, with its own JWT bearer-token auth — deliberately
    # independent of the HTML app's session cookie above (see
    # app.web.auth_views's docstring).
    from app.api import init_api

    init_api(app)

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
