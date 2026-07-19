"""``/api/v1/accounts`` (§10.4). Slice 4a's ``GET`` list reuses
``account_service.list_accounts``/``count_accounts`` exactly as the HTML
Accounts page does. Slice 4b adds the mutating routes — connect/scan/schedule
CRUD — each reusing the exact same service function as its HTML counterpart
in ``app.web.views``, gated by the same ``Capability`` the HTML route uses.
"""

from __future__ import annotations

from flask_smorest import Blueprint

from app.api.auth import current_api_user, require_api_role
from app.api.errors import ApiError
from app.api.pagination import PaginationArgsSchema, total_count_headers
from app.api.schemas import (
    AccountSchema,
    ConnectAccountRequestSchema,
    ConnectAccountResponseSchema,
    ScanResponseSchema,
    ScheduleDetailSchema,
    ScheduleRunNowResponseSchema,
    ScheduleWriteRequestSchema,
)
from app.db import session_scope
from app.domain.records import Thresholds
from app.models import Account
from app.scheduler import fire_schedule, remove_schedule_job, sync_schedule
from app.services.account_service import count_accounts, list_accounts
from app.services.connect_service import ConnectError, connect_account
from app.services.rbac import Capability, PermissionDenied
from app.services.scan_service import enqueue_scan
from app.services.schedule_service import (
    ScheduleError,
    delete_schedule,
    get_schedule,
    upsert_schedule,
)

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


def _thresholds_from(data: dict) -> Thresholds:
    base = Thresholds()
    return Thresholds(
        inactivity_days=data.get("inactivity_days", base.inactivity_days),
        password_age_days=data.get("password_age_days", base.password_age_days),
        key_age_days=data.get("key_age_days", base.key_age_days),
        failed_logins=data.get("failed_logins", base.failed_logins),
    )


@blp.route("/connect", methods=["POST"])
@require_api_role(Capability.CONNECT_ACCOUNT)
@blp.arguments(ConnectAccountRequestSchema, location="json")
@blp.response(201, ConnectAccountResponseSchema)
def connect_account_route(payload: dict) -> dict:
    """Same orchestration as ``views.connect_account_route``: validate +
    create the account (+ optional schedule) in one transaction, THEN — only
    once that's committed — hand off to the background job queue and the live
    scheduler (see ``enqueue_scan``/``sync_schedule``'s own docstrings for why
    that ordering matters)."""
    actor = current_api_user()
    thresholds = _thresholds_from(payload["thresholds"] or {})
    new_schedule_id: int | None = None
    with session_scope() as session:
        try:
            account_id = connect_account(
                session,
                name=payload["name"],
                method=payload["method"],
                thresholds=thresholds,
                role_arn=payload["role_arn"],
                external_id=payload["external_id"],
                inventory_text=payload["inventory_text"],
                policies_json=payload["policies_json"],
                logs_text=payload["logs_text"],
                actor_id=actor.id,
                actor_role=actor.role,
            )
            if payload["schedule_enabled"]:
                new_schedule = upsert_schedule(
                    session,
                    account_id=account_id,
                    cron=payload["schedule_cron"],
                    thresholds=thresholds,
                    enabled=True,
                    actor_id=actor.id,
                )
                new_schedule_id = new_schedule.id
        except (ConnectError, ScheduleError) as exc:
            raise ApiError(400, "validation_error", str(exc)) from exc
        except PermissionDenied as exc:
            # The route decorator above already gates this — reaching here
            # would mean it was somehow bypassed. Defense in depth (see
            # app.services.rbac's module docstring), not expected in practice.
            raise ApiError(403, "forbidden", str(exc)) from exc

    if new_schedule_id is not None:
        sync_schedule(new_schedule_id, cron=payload["schedule_cron"], enabled=True)
    run_id = enqueue_scan(
        account_id, thresholds=thresholds, trigger="manual", triggered_by=actor.id
    )
    return {"account_id": account_id, "run_id": run_id, "schedule_id": new_schedule_id}


@blp.route("/<int:account_id>/scan", methods=["POST"])
@require_api_role(Capability.RUN_SCAN)
@blp.response(200, ScanResponseSchema)
def rescan_account_route(account_id: int) -> dict:
    """Re-scan an existing account with its saved thresholds — mirrors
    ``views.rescan_account``'s "Scan now" exactly."""
    with session_scope() as session:
        account = session.get(Account, account_id)
        if account is None:
            raise ApiError(404, "not_found", f"Account {account_id} not found.")
        thresholds = Thresholds.from_dict(account.source_config or {})
    actor = current_api_user()
    run_id = enqueue_scan(
        account_id, thresholds=thresholds, trigger="manual", triggered_by=actor.id
    )
    return {"run_id": run_id}


@blp.route("/<int:account_id>/schedule", methods=["PUT"])
@require_api_role(Capability.MANAGE_SCHEDULE)
@blp.arguments(ScheduleWriteRequestSchema, location="json")
@blp.response(200, ScheduleDetailSchema)
def save_schedule_route(payload: dict, account_id: int) -> object:
    """Create or update the account's one recurring scan (§5.5) — mirrors
    ``views.save_schedule``. Reuses the account's OWN saved thresholds, same
    as the HTML modal (no separate threshold set collected here)."""
    actor = current_api_user()
    with session_scope() as session:
        account = session.get(Account, account_id)
        if account is None:
            raise ApiError(404, "not_found", f"Account {account_id} not found.")
        thresholds = Thresholds.from_dict(account.source_config or {})
        try:
            schedule = upsert_schedule(
                session,
                account_id=account_id,
                cron=payload["cron"],
                thresholds=thresholds,
                enabled=payload["enabled"],
                actor_id=actor.id,
            )
        except ScheduleError as exc:
            raise ApiError(400, "validation_error", str(exc)) from exc
        schedule_id = schedule.id
        session.expunge(schedule)
    sync_schedule(schedule_id, cron=payload["cron"], enabled=payload["enabled"])
    return schedule


@blp.route("/<int:account_id>/schedule", methods=["DELETE"])
@require_api_role(Capability.MANAGE_SCHEDULE)
@blp.response(204)
def delete_schedule_route(account_id: int) -> None:
    with session_scope() as session:
        schedule_id = delete_schedule(session, account_id)
    if schedule_id is not None:
        remove_schedule_job(schedule_id)


@blp.route("/<int:account_id>/schedule/run-now", methods=["POST"])
@require_api_role(Capability.MANAGE_SCHEDULE)
@blp.response(200, ScheduleRunNowResponseSchema)
def run_schedule_now_route(account_id: int) -> dict:
    """Fires the SAME function the cron trigger calls, synchronously — the
    API equivalent of the schedule editor's "Run now" (``views.run_schedule_now``)."""
    with session_scope() as session:
        schedule = get_schedule(session, account_id)
        if schedule is None:
            raise ApiError(404, "not_found", f"No schedule for account {account_id}.")
        schedule_id = schedule.id
    run_id = fire_schedule(schedule_id)
    if run_id is None:
        # Schedule was deleted/disabled in the instant between the two calls
        # above — same race window ``views.run_schedule_now`` documents.
        raise ApiError(404, "not_found", "Schedule was deleted or disabled.")
    return {"run_id": run_id}
