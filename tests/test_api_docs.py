"""Swagger UI + OpenAPI spec tests (§10.4, Phase 4 Slice 4a) — /api/docs must
actually render, and the bearerAuth security scheme must be wired so Swagger
shows the padlock on every route except login. The vendored (not CDN) JS/CSS
assets are also checked, matching this app's established no-CDN posture for
htmx/Alpine/Cytoscape.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_swagger_ui_page_renders(client) -> None:
    resp = client.get("/api/docs/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "swagger-ui-container" in body
    assert "SwaggerUIBundle" in body


def test_swagger_ui_assets_are_vendored_locally_not_a_cdn(client) -> None:
    resp = client.get("/api/docs/")
    body = resp.get_data(as_text=True)
    assert "/static/vendor/swagger-ui/" in body
    assert "cdn." not in body and "unpkg.com" not in body and "jsdelivr" not in body

    for asset in ("swagger-ui.css", "swagger-ui-bundle.js", "swagger-ui-standalone-preset.js"):
        r = client.get(f"/static/vendor/swagger-ui/{asset}")
        assert r.status_code == 200, f"{asset} not served locally"


def test_openapi_spec_is_valid_json(client) -> None:
    resp = client.get("/api/docs/openapi.json")
    assert resp.status_code == 200
    spec = resp.get_json()
    assert spec["info"]["title"] == "IAM Sentinel API"
    assert spec["openapi"].startswith("3.")


def test_bearer_auth_security_scheme_is_registered(client) -> None:
    spec = client.get("/api/docs/openapi.json").get_json()
    scheme = spec["components"]["securitySchemes"]["bearerAuth"]
    assert scheme == {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}


def test_bearer_auth_is_the_default_security_requirement(client) -> None:
    """The document-level default (inherited by every operation that doesn't
    override it) — this is what makes Swagger render the padlock on every
    route without repeating ``security: [...]`` on each one."""
    spec = client.get("/api/docs/openapi.json").get_json()
    assert spec["security"] == [{"bearerAuth": []}]


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/me",
        "/api/v1/accounts",
        "/api/v1/runs",
        "/api/v1/runs/{run_id}",
        "/api/v1/runs/{run_id}/findings",
        "/api/v1/findings",
        "/api/v1/findings/{group_id}",
        "/api/v1/principals",
        "/api/v1/principals/{principal_uid}/graph",
        "/api/v1/compliance",
        "/api/v1/checks",
    ],
)
def test_every_read_route_is_documented(client, path) -> None:
    spec = client.get("/api/docs/openapi.json").get_json()
    assert path in spec["paths"], f"{path} missing from the OpenAPI spec"
    assert "get" in spec["paths"][path]


def test_report_routes_are_documented(client) -> None:
    spec = client.get("/api/docs/openapi.json").get_json()
    assert "get" in spec["paths"]["/api/v1/runs/{run_id}/report.json"]
    assert "get" in spec["paths"]["/api/v1/runs/{run_id}/report.csv"]


def test_login_route_explicitly_has_no_security_requirement(client) -> None:
    """The one route reachable without a token — its own ``security: []``
    overrides the document-level default, so Swagger shows no padlock here."""
    spec = client.get("/api/docs/openapi.json").get_json()
    assert spec["paths"]["/api/v1/auth/login"]["post"]["security"] == []
