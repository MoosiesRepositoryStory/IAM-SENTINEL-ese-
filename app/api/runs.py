"""``/api/v1/runs`` (§10.4, Phase 4 Slice 4a) — list/detail reuse
``run_query``; findings-by-run reuses the new ``run_query.list_run_findings``
(Slice 4a addition, same table/order as ``export_service``'s own query); the
report endpoints are literally ``export_service.run_to_json``/``run_to_csv``,
unchanged, just given a route and the right ``Content-Type``.
"""

from __future__ import annotations

from flask import Response
from flask_smorest import Blueprint

from app.api.auth import require_api_role
from app.api.errors import ApiError
from app.api.pagination import PaginationArgsSchema, total_count_headers
from app.api.schemas import FindingSchema, RunSchema
from app.db import session_scope
from app.services.export_service import run_to_csv, run_to_json
from app.services.rbac import Capability
from app.services.run_query import count_runs, get_run_row, list_run_findings, list_runs

blp = Blueprint("runs", __name__, url_prefix="/api/v1/runs", description="Scan runs")


@blp.route("")
@require_api_role(Capability.VIEW)
@blp.arguments(PaginationArgsSchema, location="query")
@blp.response(200, RunSchema(many=True))
def list_runs_route(pagination: dict) -> tuple[list, int, dict]:
    with session_scope() as session:
        rows = list_runs(session, limit=pagination["limit"], offset=pagination["offset"])
        total = count_runs(session)
        for row in rows:
            session.expunge(row.run)
    return rows, 200, total_count_headers(total)


@blp.route("/<int:run_id>")
@require_api_role(Capability.VIEW)
@blp.response(200, RunSchema)
def get_run_route(run_id: int) -> object:
    with session_scope() as session:
        row = get_run_row(session, run_id)
        if row is None:
            raise ApiError(404, "not_found", f"Run {run_id} not found.")
        session.expunge(row.run)
    return row


@blp.route("/<int:run_id>/findings")
@require_api_role(Capability.VIEW)
@blp.arguments(PaginationArgsSchema, location="query")
@blp.response(200, FindingSchema(many=True))
def get_run_findings_route(pagination: dict, run_id: int) -> tuple[list, int, dict]:
    with session_scope() as session:
        if get_run_row(session, run_id) is None:
            raise ApiError(404, "not_found", f"Run {run_id} not found.")
        rows, total = list_run_findings(
            session, run_id, limit=pagination["limit"], offset=pagination["offset"]
        )
        for f in rows:
            session.expunge(f)
    return rows, 200, total_count_headers(total)


@blp.route("/<int:run_id>/report.json")
@require_api_role(Capability.VIEW)
@blp.doc(responses={200: {"description": "Run report", "content": {"application/json": {}}}})
def get_run_report_json(run_id: int) -> Response:
    with session_scope() as session:
        try:
            body = run_to_json(session, run_id)
        except ValueError as exc:
            raise ApiError(404, "not_found", str(exc)) from exc
    return Response(body, mimetype="application/json")


@blp.route("/<int:run_id>/report.csv")
@require_api_role(Capability.VIEW)
@blp.doc(responses={200: {"description": "Run report", "content": {"text/csv": {}}}})
def get_run_report_csv(run_id: int) -> Response:
    with session_scope() as session:
        run = get_run_row(session, run_id)
        if run is None:
            raise ApiError(404, "not_found", f"Run {run_id} not found.")
        body = run_to_csv(session, run_id)
    return Response(body, mimetype="text/csv")
