"""``/api/v1/principals`` (§10.4, Phase 4 Slice 4a) — reuses
``graph_view.list_principals_by_blast``/``principal_graph`` exactly as the
HTML Blast Radius pages do. ``?run_id=`` optionally overrides the default
"current completed run" (``account_service.current_completed_run_id``)."""

from __future__ import annotations

from flask_smorest import Blueprint
from marshmallow import Schema, fields

from app.api.auth import require_api_role
from app.api.errors import ApiError
from app.api.pagination import PaginationArgsSchema, total_count_headers
from app.api.schemas import PrincipalGraphSchema, PrincipalSchema
from app.db import session_scope
from app.services.account_service import current_completed_run_id
from app.services.graph_view import count_principals, list_principals_by_blast, principal_graph
from app.services.rbac import Capability

blp = Blueprint(
    "principals", __name__, url_prefix="/api/v1/principals", description="Blast-radius principals"
)


class _PrincipalListArgsSchema(PaginationArgsSchema):
    run_id = fields.Integer(load_default=None)


def _resolve_run_id(session, requested: int | None) -> int | None:  # noqa: ANN001
    return requested if requested is not None else current_completed_run_id(session)


@blp.route("")
@require_api_role(Capability.VIEW)
@blp.arguments(_PrincipalListArgsSchema, location="query")
@blp.response(200, PrincipalSchema(many=True))
def list_principals_route(args: dict) -> tuple[list, int, dict]:
    with session_scope() as session:
        run_id = _resolve_run_id(session, args["run_id"])
        if run_id is None:
            return [], 200, total_count_headers(0)
        rows = list_principals_by_blast(
            session, run_id, limit=args["limit"], offset=args["offset"]
        )
        total = count_principals(session, run_id)
    return rows, 200, total_count_headers(total)


class _RunIdArgsSchema(Schema):
    """Not a list endpoint (one graph, not a page of them) — no limit/offset."""

    run_id = fields.Integer(load_default=None)


@blp.route("/<path:principal_uid>/graph")
@require_api_role(Capability.VIEW)
@blp.arguments(_RunIdArgsSchema, location="query")
@blp.response(200, PrincipalGraphSchema)
def get_principal_graph_route(args: dict, principal_uid: str) -> object:
    with session_scope() as session:
        run_id = _resolve_run_id(session, args["run_id"])
        if run_id is None:
            raise ApiError(404, "not_found", "No completed run to derive a graph from.")
        graph = principal_graph(session, run_id, principal_uid)
        if graph is None:
            raise ApiError(404, "not_found", f"Principal {principal_uid!r} not found in run {run_id}.")
    return graph
