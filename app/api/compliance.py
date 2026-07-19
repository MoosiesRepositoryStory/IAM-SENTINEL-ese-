"""``GET /api/v1/compliance`` (§10.4, Phase 4 Slice 4a) — reuses
``compliance_view.compliance_summary`` exactly as the HTML Compliance page
does. Small, bounded result set (one row per framework — three today), so
pagination is applied in-memory rather than pushed into the service."""

from __future__ import annotations

from flask_smorest import Blueprint
from marshmallow import fields

from app.api.auth import require_api_role
from app.api.pagination import PaginationArgsSchema, total_count_headers
from app.api.schemas import ComplianceFrameworkSchema
from app.db import session_scope
from app.services.account_service import current_completed_run_id
from app.services.compliance_view import compliance_summary
from app.services.rbac import Capability

blp = Blueprint(
    "compliance", __name__, url_prefix="/api/v1/compliance", description="Compliance frameworks"
)


class _ComplianceArgsSchema(PaginationArgsSchema):
    run_id = fields.Integer(load_default=None)


@blp.route("")
@require_api_role(Capability.VIEW)
@blp.arguments(_ComplianceArgsSchema, location="query")
@blp.response(200, ComplianceFrameworkSchema(many=True))
def list_compliance_route(args: dict) -> tuple[list, int, dict]:
    with session_scope() as session:
        run_id = args["run_id"] if args["run_id"] is not None else current_completed_run_id(session)
        if run_id is None:
            return [], 200, total_count_headers(0)
        frameworks = compliance_summary(session, run_id)
    total = len(frameworks)
    page = frameworks[args["offset"] : args["offset"] + args["limit"]]
    return page, 200, total_count_headers(total)
