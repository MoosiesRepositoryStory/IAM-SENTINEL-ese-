"""``/api/v1/findings`` (§10.4). Slice 4a's ``GET`` routes reuse
``finding_query.query_findings`` (the exact function the HTML Findings table
uses) for the list, and ``finding_detail.get_finding_detail`` (the exact
function the drawer uses) for the single-finding view. ``?account_id=``
optionally overrides the default "current account" (see
``account_service.current_account`` — no account switcher exists yet, so
"current" means the most recently scanned one, same as the HTML app).

Slice 4b adds every mutating route from ``app.web.views`` (transition/
suppress/accept-risk/comment/assign, single + bulk) over this JSON API,
gated by the exact same ``Capability``. Every single-item mutation returns
the refreshed ``FindingDetailSchema`` (the same shape ``GET
/findings/{id}`` returns) instead of an HTML partial — a client that just
mutated a finding gets back the exact state a follow-up GET would show,
with no extra round trip.
"""

from __future__ import annotations

from flask import url_for
from flask_smorest import Blueprint
from marshmallow import fields

from app.api.auth import current_api_user, require_api_role
from app.api.errors import ApiError
from app.api.pagination import PaginationArgsSchema, total_count_headers
from app.api.schemas import (
    AcceptRiskRequestSchema,
    AssignRequestSchema,
    BulkAcceptRiskRequestSchema,
    BulkAssignRequestSchema,
    BulkResultSchema,
    BulkSuppressRequestSchema,
    BulkTransitionRequestSchema,
    CommentRequestSchema,
    FindingDetailSchema,
    FindingSchema,
    SuppressRequestSchema,
    TicketRequestSchema,
    TransitionRequestSchema,
)
from app.db import session_scope
from app.integrations.base import IntegrationError
from app.services.account_service import current_account
from app.services.bulk_service import bulk_assign, bulk_exception, bulk_transition
from app.services.collaboration import CommentError, add_comment, assign
from app.services.exception_service import (
    EXCEPTION_STATUSES,
    ExceptionError,
    create_exception,
    revoke_exception,
)
from app.services.finding_detail import FindingDetail, get_finding_detail
from app.services.finding_query import FindingFilters, query_findings
from app.services.rbac import Capability, PermissionDenied
from app.services.ticket_service import TicketError, create_ticket
from app.services.workflow_service import InvalidTransition, transition

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
            severity=args["severity"],
            status=args["status"],
            category=args["category"],
            search=args["q"],
        )
        page = query_findings(
            session,
            account_id,
            filters=filters,
            page_size=args["limit"],
            offset=args["offset"],
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


def _detail_or_404(session, group_id: int, actor_role: str) -> FindingDetail:  # noqa: ANN001
    detail = get_finding_detail(session, group_id, actor_role=actor_role)
    if detail is None:
        raise ApiError(404, "not_found", f"Finding group {group_id} not found.")
    return detail


def _fresh_detail(session, group_id: int, actor_role: str) -> FindingDetail:  # noqa: ANN001
    """Re-fetch after a mutation — ``get_finding_detail`` doesn't mutate the
    passed-in group, and the response should reflect the just-applied change
    (new status/exception/assignee/activity entry), same object shape as
    ``get_finding_route`` above."""
    detail = get_finding_detail(session, group_id, actor_role=actor_role)
    assert detail is not None  # mutation above already proved the group exists
    session.expunge(detail.group)
    session.expunge(detail.finding)
    return detail


@blp.route("/<int:group_id>/transition", methods=["POST"])
@require_api_role(Capability.WORKFLOW_TRANSITION)
@blp.arguments(TransitionRequestSchema, location="json")
@blp.response(200, FindingDetailSchema)
def transition_route(payload: dict, group_id: int) -> object:
    """Mirrors ``views.finding_transition``: reopening FROM an exception
    state routes through ``revoke_exception`` so the exception row closes
    out too — a plain ``transition`` call would leave it stale."""
    actor = current_api_user()
    to_status = payload["to_status"]
    with session_scope() as session:
        detail = _detail_or_404(session, group_id, actor.role)
        try:
            if to_status == "open" and detail.group.current_status in EXCEPTION_STATUSES:
                revoke_exception(
                    session,
                    detail.group,
                    actor_id=actor.id,
                    note=payload["note"] or "Exception revoked",
                )
            else:
                transition(
                    session, detail.group, to_status, actor_id=actor.id, note=payload["note"]
                )
        except InvalidTransition as exc:
            raise ApiError(409, "invalid_transition", str(exc)) from exc
        return _fresh_detail(session, group_id, actor.role)


def _apply_exception_route(group_id: int, kind: str, reason: str, expires_at: str | None) -> object:
    actor = current_api_user()
    with session_scope() as session:
        detail = _detail_or_404(session, group_id, actor.role)
        try:
            create_exception(
                session,
                detail.group,
                kind=kind,
                reason=reason,
                actor_id=actor.id,
                actor_role=actor.role,
                expires_at=expires_at,
            )
        except InvalidTransition as exc:
            raise ApiError(409, "invalid_transition", str(exc)) from exc
        except ExceptionError as exc:
            raise ApiError(400, "validation_error", str(exc)) from exc
        except PermissionDenied as exc:
            # The route decorator already gates ACCEPT_RISK_CREATE at
            # admin — reaching here would mean it was somehow bypassed.
            # Defense in depth, not expected in practice.
            raise ApiError(403, "forbidden", str(exc)) from exc
        return _fresh_detail(session, group_id, actor.role)


@blp.route("/<int:group_id>/suppress", methods=["POST"])
@require_api_role(Capability.SUPPRESS)
@blp.arguments(SuppressRequestSchema, location="json")
@blp.response(200, FindingDetailSchema)
def suppress_route(payload: dict, group_id: int) -> object:
    return _apply_exception_route(group_id, "suppressed", payload["reason"], None)


@blp.route("/<int:group_id>/accept-risk", methods=["POST"])
@require_api_role(Capability.ACCEPT_RISK_CREATE)
@blp.arguments(AcceptRiskRequestSchema, location="json")
@blp.response(200, FindingDetailSchema)
def accept_risk_route(payload: dict, group_id: int) -> object:
    return _apply_exception_route(
        group_id, "accepted_risk", payload["reason"], payload["expires_at"]
    )


@blp.route("/<int:group_id>/comment", methods=["POST"])
@require_api_role(Capability.COMMENT)
@blp.arguments(CommentRequestSchema, location="json")
@blp.response(200, FindingDetailSchema)
def comment_route(payload: dict, group_id: int) -> object:
    actor = current_api_user()
    with session_scope() as session:
        detail = _detail_or_404(session, group_id, actor.role)
        try:
            add_comment(session, detail.group, author_id=actor.id, body=payload["body"])
        except CommentError as exc:
            raise ApiError(400, "validation_error", str(exc)) from exc
        return _fresh_detail(session, group_id, actor.role)


def _parse_assignee(raw: str) -> int | None:
    """Mirrors ``views.finding_assign``'s parsing exactly (see
    ``AssignRequestSchema``'s docstring)."""
    if raw == "me":
        return current_api_user().id
    if raw in {"", "none"}:
        return None
    return int(raw) if raw.isdigit() else None


@blp.route("/<int:group_id>/assign", methods=["POST"])
@require_api_role(Capability.ASSIGN)
@blp.arguments(AssignRequestSchema, location="json")
@blp.response(200, FindingDetailSchema)
def assign_route(payload: dict, group_id: int) -> object:
    actor = current_api_user()
    assignee_id = _parse_assignee((payload["assignee_id"] or "").strip())
    with session_scope() as session:
        detail = _detail_or_404(session, group_id, actor.role)
        assign(session, detail.group, assignee_id=assignee_id, actor_id=actor.id)
        return _fresh_detail(session, group_id, actor.role)


@blp.route("/<int:group_id>/ticket", methods=["POST"])
@require_api_role(Capability.CREATE_TICKET)
@blp.arguments(TicketRequestSchema, location="json")
@blp.response(200, FindingDetailSchema)
def ticket_route(payload: dict, group_id: int) -> object:
    """Mirrors ``views.finding_create_ticket`` (§7.5) — same
    ``ticket_service.create_ticket`` call, same refreshed-detail response
    shape as every other single-item mutation in this module."""
    actor = current_api_user()
    with session_scope() as session:
        detail = _detail_or_404(session, group_id, actor.role)
        finding_url = url_for("web.finding_drawer", group_id=group_id, _external=True)
        try:
            create_ticket(
                session, detail.group, detail.finding, target_id=payload["target_id"],
                title=payload["title"], body=payload["body"], finding_url=finding_url,
                actor_id=actor.id,
            )
        except TicketError as exc:
            raise ApiError(400, "validation_error", str(exc)) from exc
        except IntegrationError as exc:
            raise ApiError(502, "integration_unreachable", str(exc)) from exc
        return _fresh_detail(session, group_id, actor.role)


# ---- bulk --------------------------------------------------------------


@blp.route("/bulk/transition", methods=["POST"])
@require_api_role(Capability.WORKFLOW_TRANSITION)
@blp.arguments(BulkTransitionRequestSchema, location="json")
@blp.response(200, BulkResultSchema)
def bulk_transition_route(payload: dict) -> object:
    actor = current_api_user()
    with session_scope() as session:
        return bulk_transition(
            session,
            payload["group_ids"],
            payload["to_status"],
            actor_id=actor.id,
            note=payload["note"],
        )


@blp.route("/bulk/assign", methods=["POST"])
@require_api_role(Capability.ASSIGN)
@blp.arguments(BulkAssignRequestSchema, location="json")
@blp.response(200, BulkResultSchema)
def bulk_assign_route(payload: dict) -> object:
    actor = current_api_user()
    assignee_id = _parse_assignee((payload["assignee_id"] or "").strip())
    with session_scope() as session:
        return bulk_assign(session, payload["group_ids"], assignee_id, actor_id=actor.id)


@blp.route("/bulk/suppress", methods=["POST"])
@require_api_role(Capability.SUPPRESS)
@blp.arguments(BulkSuppressRequestSchema, location="json")
@blp.response(200, BulkResultSchema)
def bulk_suppress_route(payload: dict) -> object:
    actor = current_api_user()
    with session_scope() as session:
        return bulk_exception(
            session,
            payload["group_ids"],
            "suppressed",
            reason=payload["reason"],
            actor_id=actor.id,
            actor_role=actor.role,
        )


@blp.route("/bulk/accept-risk", methods=["POST"])
@require_api_role(Capability.ACCEPT_RISK_CREATE)
@blp.arguments(BulkAcceptRiskRequestSchema, location="json")
@blp.response(200, BulkResultSchema)
def bulk_accept_risk_route(payload: dict) -> object:
    actor = current_api_user()
    with session_scope() as session:
        return bulk_exception(
            session,
            payload["group_ids"],
            "accepted_risk",
            reason=payload["reason"],
            actor_id=actor.id,
            actor_role=actor.role,
            expires_at=payload["expires_at"],
        )
