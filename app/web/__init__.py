"""Minimal Flask app (Phase 0).

Phase 0 keeps the web surface intentionally tiny — a health check and a landing
page that proves the app runs against the new schema. Phase 1 grows this into the
full blueprinted UX shell (sidebar, findings table, drawer, command palette).
"""

from __future__ import annotations

from flask import Flask, jsonify, render_template_string
from sqlalchemy import select

from app.config import get_settings
from app.db import init_engine, session_scope
from app.models import Account, Run

_LANDING = """<!doctype html>
<title>IAM Sentinel</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; background:#0B0E14; color:#E4E7EB;
         max-width: 760px; margin: 8vh auto; padding: 0 1.5rem; }
  h1 { font-size: 2rem; } .muted { color:#8A94A6; }
  .card { background:#131722; border:1px solid #232A36; border-radius:12px;
          padding:1rem 1.25rem; margin:1rem 0; }
  code { background:#232A36; padding:.1rem .35rem; border-radius:4px; }
</style>
<h1>🛡️ IAM Sentinel</h1>
<p class="muted">Cloud IAM posture &amp; entitlement analysis — Phase 0 backend spine.</p>
<div class="card">
  <strong>{{ accounts }}</strong> account(s), <strong>{{ runs }}</strong> scan(s) recorded.
  {% if latest %}<br>Latest run #{{ latest.id }} — score
  <strong>{{ latest.composite_score }}</strong>/100 ({{ latest.status }}).{% endif %}
</div>
<p class="muted">Run a scan from the CLI: <code>iam-sentinel scan --inventory users.csv ...</code></p>
"""


def create_app() -> Flask:
    app = Flask(__name__)
    settings = get_settings()
    app.config["SECRET_KEY"] = settings.secret_key
    init_engine(settings)

    @app.get("/healthz")
    def healthz():  # noqa: ANN202
        return jsonify(status="ok")

    @app.get("/")
    def landing():  # noqa: ANN202
        with session_scope() as session:
            accounts = session.scalars(select(Account)).all()
            runs = session.scalars(select(Run).order_by(Run.id.desc())).all()
            latest = runs[0] if runs else None
            return render_template_string(
                _LANDING,
                accounts=len(accounts),
                runs=len(runs),
                latest=latest,
            )

    return app
