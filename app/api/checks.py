"""``GET /api/v1/checks`` (§10.4, Phase 4 Slice 4a) — reuses
``checks_catalog.list_checks`` exactly as the HTML checks catalog does
(renders even pre-scan, since it's a view over the always-available rule
registry — see that module's own docstring). Small, bounded result set (~20
checks today), so pagination is applied in-memory rather than pushed into
the service."""

from __future__ import annotations

from flask_smorest import Blueprint
from marshmallow import fields

from app.api.auth import require_api_role
from app.api.pagination import PaginationArgsSchema, total_count_headers
from app.api.schemas import CheckCatalogSchema
from app.db import session_scope
from app.services.account_service import current_completed_run_id
from app.services.checks_catalog import list_checks
from app.services.rbac import Capability

blp = Blueprint("checks", __name__, url_prefix="/api/v1/checks", description="Check catalog")


class _ChecksArgsSchema(PaginationArgsSchema):
    run_id = fields.Integer(load_default=None)


@blp.route("")
@require_api_role(Capability.VIEW)
@blp.arguments(_ChecksArgsSchema, location="query")
@blp.response(200, CheckCatalogSchema(many=True))
def list_checks_route(args: dict) -> tuple[list, int, dict]:
    with session_scope() as session:
        run_id = args["run_id"] if args["run_id"] is not None else current_completed_run_id(session)
        rows = list_checks(session, run_id) if run_id is not None else list_checks()
    total = len(rows)
    page = rows[args["offset"] : args["offset"] + args["limit"]]
    return page, 200, total_count_headers(total)
