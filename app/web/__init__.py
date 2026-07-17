"""Flask application factory.

Phase 1 grows the web surface into the blueprinted UX shell: sidebar/topbar,
theme tokens, and the findings table (§8.2). Templates live in ``templates/`` and
static assets (vendored htmx + Alpine, CSS) in ``static/``.
"""

from __future__ import annotations

from flask import Flask

from app.config import get_settings
from app.db import init_engine
from app.scheduler import start_scheduler


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    settings = get_settings()
    app.config["SECRET_KEY"] = settings.secret_key
    init_engine(settings)

    from app.web.views import bp

    app.register_blueprint(bp)

    # Recurring scans + the daily exception-expiry job (§5.5 / §11.4, Slice 5).
    # start_scheduler() is idempotent, so this is safe even if create_app() is
    # ever called more than once in a process. Not called from anywhere in the
    # CLI (app/cli.py never imports create_app), so `iam-sentinel scan` stays a
    # one-shot command with no background thread — only the web app runs one.
    start_scheduler()

    return app
