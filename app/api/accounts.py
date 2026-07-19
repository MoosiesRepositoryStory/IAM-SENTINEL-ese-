"""``GET /api/v1/accounts`` (§10.4, Phase 4 Slice 4a) — reuses
``account_service.list_accounts``/``count_accounts`` exactly as the HTML
Accounts page does; this slice is read-only, so no connect/scan/schedule
mutation routes here (those land in 4b, gated the same way the HTML
``Capability.CONNECT_ACCOUNT``/``RUN_SCAN``/``MANAGE_SCHEDULE`` routes are).
"""

from __future__ import annotations

from flask_smorest import Blueprint

from app.api.auth import require_api_role
from app.api.pagination import PaginationArgsSchema, total_count_headers
from app.api.schemas import AccountSchema
from app.db import session_scope
from app.services.account_service import count_accounts, list_accounts
from app.services.rbac import Capability

blp = Blueprint(
    "accounts", __name__, url_prefix="/api/v1/accounts", description="Connected accounts"
)


@blp.route("")
@require_api_role(Capability.VIEW)
@blp.arguments(PaginationArgsSchema, location="query")
@blp.response(200, AccountSchema(many=True))
def list_accounts_route(pagination: dict) -> tuple[list, int, dict]:
    with session_scope() as session:
        rows = list_accounts(session, limit=pagination["limit"], offset=pagination["offset"])
        total = count_accounts(session)
        for row in rows:
            session.expunge(row.account)
            if row.latest_run is not None:
                session.expunge(row.latest_run)
            if row.schedule is not None:
                session.expunge(row.schedule)
    return rows, 200, total_count_headers(total)
