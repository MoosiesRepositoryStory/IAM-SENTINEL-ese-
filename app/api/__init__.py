"""OpenAPI /api/v1 (§10.4, Phase 4 Slice 4a): a flask-smorest blueprint tree
mounted on the SAME Flask app as the HTML UI (``app.web``), but with its own
JWT bearer-token auth — deliberately separate from the HTML app's session
cookie (see ``app.web.auth_views``'s docstring for why they share one app but
not one login mechanism). This slice is read-only; mutations land in 4b.
"""

from __future__ import annotations

from flask import Flask
from flask_smorest import Api

from app.api.errors import register_error_handlers
from app.api.schemas import ErrorEnvelopeSchema

api = Api()
# The generated "default error response" doc for every operation should
# describe this app's REAL envelope (see app.api.errors), not
# flask-smorest's own built-in error shape.
api.ERROR_SCHEMA = ErrorEnvelopeSchema


def init_api(app: Flask) -> None:
    """Configure and mount the API onto ``app`` — called once from
    ``app.web.create_app()``."""
    app.config["API_TITLE"] = "IAM Sentinel API"
    app.config["API_VERSION"] = "v1"
    app.config["OPENAPI_VERSION"] = "3.0.3"
    app.config["OPENAPI_URL_PREFIX"] = "/api/docs"
    # Swagger UI itself lives at /api/docs/ (flask-smorest mounts it under
    # OPENAPI_URL_PREFIX); its JS/CSS assets are vendored locally (same
    # no-CDN posture as htmx/Alpine/Cytoscape — see app/web/static/vendor/)
    # rather than pulled from a CDN, so the docs page (and anything that
    # verifies it, e.g. Playwright) works fully offline.
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/"
    app.config["OPENAPI_SWAGGER_UI_URL"] = "/static/vendor/swagger-ui/"

    # `security` as a top-level APISpec option becomes the OpenAPI document's
    # default `security` requirement (apispec forwards unrecognized kwargs
    # straight into the spec root) — every operation inherits "needs
    # bearerAuth" unless it explicitly overrides its own `security`, which is
    # exactly what the login route does (@blp.doc(security=[])), since that's
    # the one endpoint reachable without a token.
    api.init_app(app, spec_kwargs={"security": [{"bearerAuth": []}]})

    # Registers the scheme itself so Swagger can resolve what "bearerAuth"
    # means and render the padlock + an "Authorize" dialog for it.
    api.spec.components.security_scheme(
        "bearerAuth", {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
    )

    from app.api.accounts import blp as accounts_blp
    from app.api.auth import blp as auth_blp
    from app.api.checks import blp as checks_blp
    from app.api.compliance import blp as compliance_blp
    from app.api.findings import blp as findings_blp
    from app.api.me import blp as me_blp
    from app.api.principals import blp as principals_blp
    from app.api.runs import blp as runs_blp

    api.register_blueprint(auth_blp)
    api.register_blueprint(me_blp)
    api.register_blueprint(accounts_blp)
    api.register_blueprint(runs_blp)
    api.register_blueprint(findings_blp)
    api.register_blueprint(principals_blp)
    api.register_blueprint(compliance_blp)
    api.register_blueprint(checks_blp)

    register_error_handlers(app)
