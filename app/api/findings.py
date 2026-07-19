"""``/api/v1/findings`` (§10.4, Phase 4 Slice 4a) — reuses
``finding_query.query_findings`` (the exact function the HTML Findings table
uses) for the list, and ``finding_detail.get_finding_detail`` (the exact
function the drawer uses) for the single-finding view. ``?account_id=``
optionally overrides the default "current account" (see
``account_service.current_account`` — no account switcher exists yet, so
"current" means the most recently scanned one, same as the HTML app)."""

from __future__ import annotations

from flask_smorest import Blueprint
from marshmallow import fields

from app.api.auth import current_api_user, require_api_role
from app.api.errors import ApiError
from app.api.pagination import PaginationArgsSchema, total_count_headers
from app.api.schemas import FindingDetailSchema, FindingSchema
from app.db import session_scope
from app.services.account_service import current_account
from app.services.finding_detail import get_finding_detail
from app.services.finding_query import FindingFilters, query_findings
from app.services.rbac import Capability

blp = Blueprint("findings", __name__, url_prefix="/api/v1/findings", description="Findings")


class _FindingListArgsSchema(PaginationArgsSchema):
    account_id = fields.Integer(load_default=None)
    severity = fields.List(fields.String(), load_default=list)
    status = fields.List(fields.String(), load_default=list)
    category = fields.List(fields.String(), load_default=list)
    q = fields.String(load_default="")


@blp.route("")
@require_api_role(Capability.VIEW)
@blp.arguments(_FindingListArgsSchema, location="query")
@blp.response(200, FindingSchema(many=True))
def list_findings_route(args: dict) -> tuple[list, int, dict]:
    with session_scope() as session:
        account_id = args["account_id"]
        if account_id is None:
            account = current_account(session)
            if account is None:
                return [], 200, total_count_headers(0)
            account_id = account.id
        filters = FindingFilters(
            severity=args["severity"], status=args["status"], category=args["category"],
            search=args["q"],
        )
        page = query_findings(
            session, account_id, filters=filters,
            page_size=args["limit"], offset=args["offset"],
        )
        for row in page.rows:
            session.expunge(row)
    return page.rows, 200, total_count_headers(page.total)


@blp.route("/<int:group_id>")
@require_api_role(Capability.VIEW)
@blp.response(200, FindingDetailSchema)
def get_finding_route(group_id: int) -> object:
    with session_scope() as session:
        detail = get_finding_detail(session, group_id, actor_role=current_api_user().role)
        if detail is None:
            raise ApiError(404, "not_found", f"Finding group {group_id} not found.")
        session.expunge(detail.group)
        session.expunge(detail.finding)
    return detail
