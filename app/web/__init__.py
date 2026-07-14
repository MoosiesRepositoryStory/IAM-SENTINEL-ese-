"""Flask application factory.

Phase 1 grows the web surface into the blueprinted UX shell: sidebar/topbar,
theme tokens, and the findings table (§8.2). Templates live in ``templates/`` and
static assets (vendored htmx + Alpine, CSS) in ``static/``.
"""

from __future__ import annotations

from flask import Flask

from app.config import get_settings
from app.db import init_engine


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    settings = get_settings()
    app.config["SECRET_KEY"] = settings.secret_key
    init_engine(settings)

    from app.web.views import bp

    app.register_blueprint(bp)

    return app
