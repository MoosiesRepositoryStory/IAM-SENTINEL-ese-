"""Web UI blueprint — Phase 1 Slice 1 (app shell + findings table read path).

Routes serve two shapes of the same data: full pages (with the shell) and, for
htmx requests, just the table partial so sort/filter/paginate swaps are cheap and
never reload the shell. The ``HX-Request`` header tells them apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from flask import Blueprint, Response, abort, redirect, render_template, request, url_for
from flask_login import current_user

from app.db import session_scope
from app.domain.records import Thresholds
from app.integrations.base import IntegrationError
from app.models import Account, RunSummary
from app.scheduler import fire_schedule, remove_schedule_job, sync_schedule
from app.services.account_service import current_account as _current_account
from app.services.account_service import (
    current_completed_run_id as _current_completed_run_id,
)
from app.services.account_service import list_accounts
from app.services.bulk_service import bulk_assign, bulk_exception, bulk_transition
from app.services.checks_catalog import list_checks
from app.services.collaboration import CommentError, active_users, add_comment, assign
from app.services.compliance_view import compliance_summary
from app.services.connect_service import ConnectError, connect_account
from app.services.dashboard import build_dashboard
from app.services.diff_service import DiffError, default_diff_pair, diff
from app.services.exception_service import (
    EXCEPTION_STATUSES,
    ExceptionError,
    active_exceptions,
    create_exception,
    expire_exceptions,
    revoke_exception,
)
from app.services.finding_detail import get_finding_detail
from app.services.finding_query import (
    FindingFilters,
    assignee_names,
    parse_filters,
    parse_sort,
    query_findings,
    sort_to_query,
)
from app.services.graph_view import list_principals_by_blast, principal_graph
from app.services.integration_service import list_enabled_targets
from app.services.rbac import Capability, PermissionDenied, at_least
from app.services.run_query import get_run_row, list_runs, score_trend
from app.services.scan_service import enqueue_scan
from app.services.schedule_service import (
    ScheduleError,
    delete_schedule,
    get_schedule,
    upsert_schedule,
)
from app.services.ticket_service import TicketError, create_ticket
from app.services.workflow_service import (
    STATUS_LABELS,
    InvalidTransition,
    available_actions,
    transition,
)
from app.web.authz import require_role

bp = Blueprint("web", __name__)
# Single source of truth for the row-level context menu's "Change status" /
# "Suppress" / "Accept risk" items (§8.3) — the exact function the drawer
# footer already uses. Registered so findings_table.html can call it per row
# without a Python-side per-row loop.
bp.add_app_template_global(available_actions)
# Lets templates gate a control on role without importing rbac themselves
# (§10.2) — e.g. {% if role_at_least(current_user.role, 'analyst') %}.
bp.add_app_template_global(at_least, name="role_at_least")

# Routes reachable without a session — everything else on this blueprint
# requires login (§10.1). Static files aren't affected either way: they're
# served by Flask's app-level `static` endpoint, never part of this blueprint,
# so a blueprint-scoped before_request never even runs for them.
_PUBLIC_ENDPOINTS = {"web.login", "web.healthz"}


@bp.before_request
def _require_login() -> Response | None:
    if request.endpoint in _PUBLIC_ENDPOINTS:
        return None
    if current_user.is_authenticated:
        return None
    if request.headers.get("HX-Request") == "true":
        # A redirect() response body can't usefully swap into an htmx target;
        # HX-Redirect tells htmx to do a full top-level navigation instead.
        resp = Response(status=200)
        resp.headers["HX-Redirect"] = url_for("web.login")
        return resp
    return cast(Response, redirect(url_for("web.login", next=request.path)))


# Column definitions drive both the header row and the "Columns" menu (§8.2).
# ``key`` matches finding_query._SORTABLE where sortable; ``default`` = shown.
COLUMNS: list[dict[str, str | bool]] = [
    {"key": "risk", "label": "Risk", "sortable": True, "default": True},
    {"key": "severity", "label": "Severity", "sortable": True, "default": True},
    {"key": "status", "label": "Status", "sortable": True, "default": True},
    {"key": "title", "label": "Title", "sortable": True, "default": True},
    {"key": "principal", "label": "Principal", "sortable": True, "default": True},
    {"key": "category", "label": "Category", "sortable": True, "default": True},
    {"key": "assignee", "label": "Assignee", "sortable": False, "default": True},
    {"key": "compliance", "label": "Compliance", "sortable": False, "default": True},
    {"key": "last_seen", "label": "Last seen", "sortable": True, "default": True},
    {"key": "first_seen", "label": "First seen", "sortable": True, "default": False},
    {"key": "check", "label": "Check ID", "sortable": True, "default": False},
]
_DEFAULT_COLS: list[str] = [str(c["key"]) for c in COLUMNS if c["default"]]


def _selected_columns() -> list[str]:
    raw = request.args.get("cols")
    if not raw:
        return _DEFAULT_COLS
    wanted = raw.split(",")
    valid = {str(c["key"]) for c in COLUMNS}
    ordered = [k for k in wanted if k in valid]
    return ordered or _DEFAULT_COLS


def _page_arg() -> int:
    try:
        return max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        return 1


@bp.get("/")
@bp.get("/dashboard")
def index() -> Response | str:
    """Account posture dashboard (§8.11 / §6.4) — the retuned posture gauge,
    grade, score trend, severity mix, and riskiest principals for the latest
    completed run. Falls back to the empty state before the first scan."""
    with session_scope() as session:
        account = _current_account(session)
        run_id = _current_completed_run_id(session)
        if account is None or run_id is None:
            return render_template("empty_state.html", reason="no_data", columns=COLUMNS)
        data = build_dashboard(session, run_id)
        trend = score_trend(session, account.id)
        frameworks = compliance_summary(session, run_id)
        summary = session.get(RunSummary, run_id)
        new_count = summary.new_count if summary else None
        resolved_count = summary.resolved_count if summary else None
        gauge = _gauge_geometry(data.posture)
        session.expunge(data.run)
    return render_template(
        "dashboard.html",
        d=data,
        gauge=gauge,
        trend=trend,
        spark_points=_sparkline_points(trend, width=200, height=44),
        frameworks=frameworks,
        new_count=new_count,
        resolved_count=resolved_count,
    )


@bp.get("/findings")
def findings() -> Response | str:
    return _render_findings(full_page=not _is_htmx())


# -- Accounts + Connect wizard (§5.3, Slice 2) -------------------------------


def _expunge_account_rows(session, rows) -> None:  # noqa: ANN001
    """Detach each row's ORM instances so template access after the session
    closes doesn't lazy-load (same discipline as ``_render_findings``)."""
    for row in rows:
        session.expunge(row.account)
        if row.latest_run is not None:
            session.expunge(row.latest_run)
        if row.schedule is not None:
            session.expunge(row.schedule)


def _parse_thresholds() -> Thresholds:
    base = Thresholds()

    def _int(key: str, default: int) -> int:
        try:
            return int(request.form.get(key, default))
        except (TypeError, ValueError):
            return default

    return Thresholds(
        inactivity_days=_int("inactivity_days", base.inactivity_days),
        password_age_days=_int("password_age_days", base.password_age_days),
        key_age_days=_int("key_age_days", base.key_age_days),
        failed_logins=_int("failed_logins", base.failed_logins),
    )


def _read_upload(field: str) -> str | None:
    file = request.files.get(field)
    if file is None or not file.filename:
        return None
    return file.read().decode("utf-8", errors="replace")


@bp.get("/accounts")
def accounts() -> Response | str:
    with session_scope() as session:
        rows = list_accounts(session)
        current = _current_account(session)
        current_id = current.id if current is not None else None
        _expunge_account_rows(session, rows)
    return render_template(
        "accounts.html",
        rows=rows,
        current_account_id=current_id,
        default_thresholds=Thresholds().to_dict(),
    )


@bp.post("/accounts/connect")
@require_role(Capability.CONNECT_ACCOUNT)
def connect_account_route() -> Response | str | tuple[str, int]:
    name = request.form.get("name", "")
    method = request.form.get("method", "demo")
    role_arn = request.form.get("role_arn", "")
    external_id = request.form.get("external_id", "")
    thresholds = _parse_thresholds()
    schedule_enabled = request.form.get("schedule_enabled") == "on"
    schedule_cron = request.form.get("schedule_cron", "")
    account_id: int | None = None
    actor_id: int | None = None
    new_schedule_id: int | None = None
    with session_scope() as session:
        actor = current_user
        actor_id = actor.id
        try:
            account_id = connect_account(
                session,
                name=name,
                method=method,
                thresholds=thresholds,
                role_arn=role_arn,
                external_id=external_id,
                inventory_text=_read_upload("inventory_file"),
                policies_json=_read_upload("policies_file"),
                logs_text=_read_upload("logs_file"),
                actor_id=actor.id,
                actor_role=actor.role,
            )
            # Step 3's optional "recurring scan" fields (§5.3 step 3 / §5.5) —
            # reuses the same thresholds just collected for the account, so the
            # schedule and the account's default scan are never out of sync at
            # creation time. Committed in the SAME transaction as the account
            # (below), so either both exist or neither does.
            if schedule_enabled:
                new_schedule = upsert_schedule(
                    session,
                    account_id=account_id,
                    cron=schedule_cron,
                    thresholds=thresholds,
                    enabled=True,
                    actor_id=actor.id,
                )
                new_schedule_id = new_schedule.id
        except (ConnectError, ScheduleError, PermissionDenied) as exc:
            # PermissionDenied here would mean the route decorator above was
            # somehow bypassed — the defense-in-depth re-check inside
            # connect_account() catching what it's not supposed to reach.
            # Rendered as a normal wizard error rather than a 500, but this
            # path should be unreachable in practice.
            rows = list_accounts(session)
            current = _current_account(session)
            current_id = current.id if current is not None else None
            _expunge_account_rows(session, rows)
            # ARN/upload validation errors live on step 2's fields; a missing
            # name or bad cron is only visible on step 3 — reopen wherever the
            # bad field actually is rather than always landing on step 3.
            # (connect_account/upsert_schedule only ever raise for input
            # validation — a scan-execution failure surfaces later as a
            # `failed` Run on the Runs page, not here.)
            msg = str(exc)
            wizard_step = 2 if ("Role ARN" in msg or "Upload at least" in msg) else 3
            return render_template(
                "accounts.html",
                rows=rows,
                current_account_id=current_id,
                default_thresholds=Thresholds().to_dict(),
                error=msg,
                wizard_open=True,
                wizard_step=wizard_step,
                form_values={
                    "name": name,
                    "method": method,
                    "role_arn": role_arn,
                    "external_id": external_id,
                    "schedule_enabled": schedule_enabled,
                    "schedule_cron": schedule_cron,
                },
            ), 400
    # The account (+ schedule, if any) row is committed now (the `with` block
    # above closed) — safe to hand off to the background job queue, whose
    # worker thread opens its own fresh session and needs to see it
    # immediately, and to register the new schedule with the live in-process
    # scheduler (an in-process side effect, deliberately done only after the
    # DB row it reads back on every fire is durable).
    if new_schedule_id is not None:
        sync_schedule(new_schedule_id, cron=schedule_cron, enabled=True)
    run_id = enqueue_scan(
        account_id, thresholds=thresholds, trigger="manual", triggered_by=actor_id
    )
    return cast(Response, redirect(url_for("web.runs", highlight=run_id)))


@bp.post("/accounts/<int:account_id>/scan")
@require_role(Capability.RUN_SCAN)
def rescan_account(account_id: int) -> Response:
    """Re-scan an existing account with its saved thresholds (§5.3 step 5's
    "Scan now"), via the background job queue — lands on the Runs page to
    watch it progress rather than Findings, which would still show the
    *previous* scan's results until this one actually completes."""
    with session_scope() as session:
        account = session.get(Account, account_id)
        if account is None:
            abort(404)
        actor = current_user
        actor_id = actor.id
        thresholds = Thresholds.from_dict(account.source_config or {})
    run_id = enqueue_scan(
        account_id, thresholds=thresholds, trigger="manual", triggered_by=actor_id
    )
    return cast(Response, redirect(url_for("web.runs", highlight=run_id)))


# -- Recurring-scan schedule CRUD (§5.5 / §11.4, Slice 5) --------------------


@bp.post("/accounts/<int:account_id>/schedule")
@require_role(Capability.MANAGE_SCHEDULE)
def save_schedule(account_id: int) -> Response | str | tuple[str, int]:
    """Create or update the account's recurring scan. One schedule per
    account (see schedule_service's module docstring) — reuses the account's
    OWN saved thresholds rather than collecting a second set in the modal."""
    cron = request.form.get("cron", "")
    enabled = request.form.get("enabled") == "on"
    schedule_id: int | None = None
    with session_scope() as session:
        account = session.get(Account, account_id)
        if account is None:
            abort(404)
        actor = current_user
        thresholds = Thresholds.from_dict(account.source_config or {})
        try:
            schedule = upsert_schedule(
                session,
                account_id=account_id,
                cron=cron,
                thresholds=thresholds,
                enabled=enabled,
                actor_id=actor.id,
            )
        except ScheduleError as exc:
            rows = list_accounts(session)
            current = _current_account(session)
            current_id = current.id if current is not None else None
            # upsert_schedule validates before touching any row (see its
            # docstring), so `rows` here still reflects whatever schedule
            # existed BEFORE this failed attempt — exactly what the reopened
            # modal needs to decide whether to show Delete/Run now.
            existing = next((r.schedule for r in rows if r.account.id == account_id), None)
            _expunge_account_rows(session, rows)
            return render_template(
                "accounts.html",
                rows=rows,
                current_account_id=current_id,
                default_thresholds=Thresholds().to_dict(),
                error=str(exc),
                schedule_open_for=account_id,
                schedule_form_values={
                    "cron": cron,
                    "enabled": enabled,
                    "exists": existing is not None,
                },
            ), 400
        schedule_id = schedule.id
    sync_schedule(schedule_id, cron=cron, enabled=enabled)
    return cast(Response, redirect(url_for("web.accounts")))


@bp.post("/accounts/<int:account_id>/schedule/delete")
@require_role(Capability.MANAGE_SCHEDULE)
def delete_schedule_route(account_id: int) -> Response:
    with session_scope() as session:
        schedule_id = delete_schedule(session, account_id)
    if schedule_id is not None:
        remove_schedule_job(schedule_id)
    return cast(Response, redirect(url_for("web.accounts")))


@bp.post("/accounts/<int:account_id>/schedule/run-now")
@require_role(Capability.MANAGE_SCHEDULE)
def run_schedule_now(account_id: int) -> Response:
    """The schedule editor's "Run now" override (§5.5) — fires the SAME
    function the cron trigger calls, synchronously, rather than a separate
    code path. Doesn't wait for APScheduler at all, so it's also how the
    Playwright check exercises a "fire" without touching wall-clock time."""
    with session_scope() as session:
        schedule = get_schedule(session, account_id)
        if schedule is None:
            abort(404)
        schedule_id = schedule.id
    run_id = fire_schedule(schedule_id)
    if run_id is None:
        abort(404)  # schedule was deleted/disabled in the instant between the two queries above
    return cast(Response, redirect(url_for("web.runs", highlight=run_id)))


# -- Runs page + live progress polling (§8.10, Slice 3) ----------------------


@bp.get("/runs")
def runs() -> Response | str:
    with session_scope() as session:
        rows = list_runs(session)
        current_run_id = _current_completed_run_id(session)
        account = _current_account(session)
        # Gate the "Compare" button on a diffable pair actually existing, so it
        # can't lead to the "nothing to compare yet" dead end (§8.9 entry point).
        can_compare = account is not None and default_diff_pair(session, account.id) is not None
        for row in rows:
            session.expunge(row.run)
    highlight_id = request.args.get("highlight", type=int)
    return render_template(
        "runs.html",
        rows=rows,
        current_run_id=current_run_id,
        highlight_id=highlight_id,
        can_compare=can_compare,
    )


@bp.get("/runs/<int:run_id>/progress")
def run_progress(run_id: int) -> Response | str:
    """Poll target for one Runs-page row: htmx re-fetches this on an interval
    until the row it gets back is terminal (completed/failed/canceled) and
    stops including its own poll trigger — at which point htmx has nothing
    left to re-fire and simply stops. No custom JS needed for this."""
    with session_scope() as session:
        row = get_run_row(session, run_id)
        if row is None:
            abort(404)
        current_run_id = _current_completed_run_id(session)
        session.expunge(row.run)
    highlight_id = request.args.get("highlight", type=int)
    return render_template(
        "partials/run_row.html", row=row, current_run_id=current_run_id, highlight_id=highlight_id
    )


# -- Blast Radius / permission graph (§6.2, Phase 3 Slice 2) ----------------


@bp.get("/graph")
def graph_overview() -> Response | str:
    with session_scope() as session:
        run_id = _current_completed_run_id(session)
        if run_id is None:
            return render_template("empty_state.html", reason="no_data", columns=COLUMNS)
        rows = list_principals_by_blast(session, run_id)
    return render_template("graph_overview.html", rows=rows)


@bp.get("/principals/<path:principal_uid>")
def principal_detail(principal_uid: str) -> Response | str:
    with session_scope() as session:
        run_id = _current_completed_run_id(session)
        if run_id is None:
            abort(404)
        graph = principal_graph(session, run_id, principal_uid)
    if graph is None:
        abort(404)
    return render_template("principal_graph.html", graph=graph)


# -- Compliance + checks catalog (§6.5 / §8.11, Phase 3 Slice 4) ------------


@bp.get("/compliance")
def compliance() -> Response | str:
    with session_scope() as session:
        run_id = _current_completed_run_id(session)
        if run_id is None:
            return render_template("empty_state.html", reason="no_data", columns=COLUMNS)
        frameworks = compliance_summary(session, run_id)
    return render_template("compliance.html", frameworks=frameworks)


@bp.get("/checks")
def checks_catalog() -> Response | str:
    with session_scope() as session:
        run_id = _current_completed_run_id(session)
        rows = list_checks(session, run_id) if run_id is not None else list_checks()
    return render_template("checks_catalog.html", rows=rows, has_run=run_id is not None)


# -- Run diff view (§5.4 / §8.9, Slice 4) ------------------------------------


def _gauge_geometry(score: int) -> dict[str, float]:
    """SVG ring-gauge geometry for a 0-100 posture score, computed server-side
    (no JS/CDN — same offline posture as the sparkline). The arc is a fraction
    ``score/100`` of a full ring; the template rotates it to start at 12 o'clock
    and colors it by grade."""
    import math

    r = 54.0
    circ = 2 * math.pi * r
    filled = circ * max(0, min(100, score)) / 100
    return {"r": r, "circ": round(circ, 2), "filled": round(filled, 2)}


def _sparkline_points(trend: list, width: int = 160, height: int = 32) -> str:  # noqa: ANN001
    """Project a score trend onto an SVG polyline's ``points`` attribute.

    Done server-side because it's arithmetic, not interaction — shipping a
    charting library (or any JS at all) for a 30-point sparkline would be
    absurd, and this keeps the offline/no-CDN property the app has held since
    Slice 1. The y-axis is pinned to the score's real 0-100 domain rather than
    auto-fitted to min/max, so a flat-but-terrible run reads as a line along
    the bottom instead of being rescaled to look mid-range.
    """
    if not trend:
        return ""
    pad = 3.0
    inner_h = height - 2 * pad
    if len(trend) == 1:
        y = pad + inner_h * (1 - trend[0].score / 100)
        return f"0,{y:.1f} {width},{y:.1f}"
    step = width / (len(trend) - 1)
    return " ".join(
        f"{i * step:.1f},{pad + inner_h * (1 - p.score / 100):.1f}" for i, p in enumerate(trend)
    )


@bp.get("/runs/diff")
def runs_diff() -> Response | str | tuple[str, int]:
    """Three-column diff board (§8.9). ``?a=&b=`` selects the runs; with either
    missing we fall back to the account's previous-vs-latest completed pair,
    which is what every entry point (Runs "Compare", the dashboard strip) wants
    anyway."""
    a = request.args.get("a", type=int)
    b = request.args.get("b", type=int)
    # Everything the template touches is resolved inside this scope; the two
    # early returns below render while the session is still open, so they need
    # no expunging. Only the success path renders after it closes.
    with session_scope() as session:
        account = _current_account(session)
        if account is None:
            return render_template("empty_state.html", reason="no_data", columns=COLUMNS)

        if a is None or b is None:
            pair = default_diff_pair(session, account.id)
            if pair is None:
                # Fewer than two completed scans — nothing to compare yet. A
                # normal state on a freshly connected account, not an error.
                return render_template(
                    "run_diff.html", account=account, d=None, runs=list_runs(session)
                )
            a, b = pair

        try:
            d = diff(session, a, b)
        except DiffError as exc:
            return render_template(
                "run_diff.html", account=account, d=None, runs=list_runs(session), error=str(exc)
            ), 400

        trend = score_trend(session, account.id)
        rows = list_runs(session)
        return render_template(
            "run_diff.html",
            account=account,
            d=d,
            runs=rows,
            trend=trend,
            spark_points=_sparkline_points(trend),
        )


def _render_drawer(session, group_id: int, **extra) -> str:  # noqa: ANN001, ANN003
    """Render the drawer partial for ``group_id`` (404s if missing). ``extra``
    passes flags like ``oob_status`` / ``oob_assignee`` / ``error``. Always
    resolves actions for the CURRENT caller's role (§10.2), so the footer
    buttons and the row's data-actions never offer more than the viewer is
    actually allowed to do."""
    detail = get_finding_detail(session, group_id, actor_role=current_user.role)
    if detail is None:
        abort(404)
    return render_template(
        "partials/finding_drawer.html",
        d=detail,
        status_labels=STATUS_LABELS,
        users=active_users(session),
        integration_targets=list_enabled_targets(session),
        **extra,
    )


@bp.get("/findings/<int:group_id>")
def finding_drawer(group_id: int) -> Response | str:
    """Finding detail drawer (§8.8). htmx → the drawer partial; a direct visit
    (deep link, §8.11) → the full findings page with the drawer auto-opened.

    Optional ``?tab=`` opens on a specific tab (used by the context menu's "View
    evidence" / "Add comment…" items) and ``?action=suppressed|accepted_risk|
    create_ticket`` also pre-reveals that exception form / the create-ticket
    modal (used by "Suppress finding…" / "Accept risk…" / "Create ticket…") —
    all reuse markup/routes already built in earlier slices, just pre-seeded.
    """
    tab = request.args.get("tab")
    action = request.args.get("action")
    if not _is_htmx():
        return _render_findings(full_page=True, open_group=group_id)
    with session_scope() as session:
        expire_exceptions(session)  # re-surface anything whose expiry has passed
        return _render_drawer(session, group_id, focus_tab=tab, open_action=action)


@bp.post("/findings/<int:group_id>/transition")
@require_role(Capability.WORKFLOW_TRANSITION)
def finding_transition(group_id: int) -> Response | str | tuple[str, int]:
    """Apply a status change and return the refreshed drawer plus an out-of-band
    swap for the table row's status pill. Reopening from suppressed/accepted-risk
    is routed through ``revoke_exception`` so the exception row closes out too —
    a plain ``transition`` call would leave it stale."""
    to_status = (request.form.get("to_status") or "").strip()
    note = request.form.get("note")
    with session_scope() as session:
        detail = get_finding_detail(session, group_id)
        if detail is None:
            abort(404)
        actor = current_user
        try:
            if to_status == "open" and detail.group.current_status in EXCEPTION_STATUSES:
                revoke_exception(
                    session, detail.group, actor_id=actor.id, note=note or "Exception revoked"
                )
            else:
                transition(session, detail.group, to_status, actor_id=actor.id, note=note)
        except InvalidTransition as exc:
            return _render_drawer(session, group_id, error=str(exc)), 409
        return _render_drawer(session, group_id, oob_status=True)


def _apply_exception(group_id: int, kind: str) -> Response | str | tuple[str, int]:
    reason = request.form.get("reason") or ""
    expires_at = request.form.get("expires_at") or None
    with session_scope() as session:
        detail = get_finding_detail(session, group_id)
        if detail is None:
            abort(404)
        actor = current_user
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
            return _render_drawer(session, group_id, error=str(exc)), 409
        except (ExceptionError, PermissionDenied) as exc:
            # PermissionDenied here means the route decorator below was
            # somehow bypassed — should be unreachable in practice, rendered
            # as a normal 400 rather than a 500.
            return _render_drawer(session, group_id, error=str(exc)), 400
        return _render_drawer(session, group_id, oob_status=True)


@bp.post("/findings/<int:group_id>/suppress")
@require_role(Capability.SUPPRESS)
def finding_suppress(group_id: int) -> Response | str | tuple[str, int]:
    """Suppress a finding: requires a reason, no expiry (§7.4 — suppression is
    "don't show me this", not time-boxed)."""
    return _apply_exception(group_id, "suppressed")


@bp.post("/findings/<int:group_id>/accept-risk")
@require_role(Capability.ACCEPT_RISK_CREATE)
def finding_accept_risk(group_id: int) -> Response | str | tuple[str, int]:
    """Accept risk on a finding: requires a reason, optional expiry after which
    it auto-reopens (§7.4)."""
    return _apply_exception(group_id, "accepted_risk")


@bp.post("/findings/<int:group_id>/comment")
@require_role(Capability.COMMENT)
def finding_comment(group_id: int) -> Response | str | tuple[str, int]:
    """Add a comment and return the refreshed drawer (Activity tab focused)."""
    body = request.form.get("body") or ""
    with session_scope() as session:
        detail = get_finding_detail(session, group_id)
        if detail is None:
            abort(404)
        author = current_user
        try:
            add_comment(session, detail.group, author_id=author.id, body=body)
        except CommentError as exc:
            return _render_drawer(session, group_id, error=str(exc), focus_tab="activity"), 400
        return _render_drawer(session, group_id, focus_tab="activity")


@bp.post("/findings/<int:group_id>/assign")
@require_role(Capability.ASSIGN)
def finding_assign(group_id: int) -> Response | str:
    """Assign/unassign the finding and return the refreshed drawer plus an
    out-of-band swap for the table row's assignee cell. ``assignee_id`` may be
    'me', '' / 'none' (unassign), or a user id."""
    raw = (request.form.get("assignee_id") or "").strip()
    with session_scope() as session:
        detail = get_finding_detail(session, group_id)
        if detail is None:
            abort(404)
        actor = current_user
        if raw == "me":
            assignee_id: int | None = actor.id
        elif raw in {"", "none"}:
            assignee_id = None
        else:
            assignee_id = int(raw) if raw.isdigit() else None
        assign(session, detail.group, assignee_id=assignee_id, actor_id=actor.id)
        return _render_drawer(session, group_id, oob_assignee=True)


@bp.post("/findings/<int:group_id>/ticket")
@require_role(Capability.CREATE_TICKET)
def finding_create_ticket(group_id: int) -> Response | str | tuple[str, int]:
    """Create a ticket/notification via a configured integration target
    (§7.5) and return the refreshed drawer, which now shows the ticket chip.
    ``title``/``body`` come from the modal, prefilled client-side from the
    finding but editable — the server takes whatever was actually submitted."""
    target_id = request.form.get("target_id", type=int)
    title = request.form.get("title", "")
    body = request.form.get("body", "")
    with session_scope() as session:
        detail = get_finding_detail(session, group_id)
        if detail is None:
            abort(404)
        actor = current_user
        finding_url = url_for("web.finding_drawer", group_id=group_id, _external=True)
        try:
            if target_id is None:
                raise TicketError("Choose an integration target.")
            create_ticket(
                session,
                detail.group,
                detail.finding,
                target_id=target_id,
                title=title,
                body=body,
                finding_url=finding_url,
                actor_id=actor.id,
            )
        except (TicketError, IntegrationError) as exc:
            # open_action keeps the modal open (rather than the generic
            # top-of-drawer error banner, which would render hidden behind
            # the modal's own backdrop) so the user sees why and can retry
            # without reopening it from scratch; ticket_form_values preserves
            # what they typed rather than resetting to the prefilled defaults.
            return _render_drawer(
                session,
                group_id,
                open_action="create_ticket",
                ticket_error=str(exc),
                ticket_form_values={"target_id": target_id, "title": title, "body": body},
            ), 400
        return _render_drawer(session, group_id)


def _is_htmx() -> bool:
    return request.headers.get("HX-Request") == "true"


def _parse_group_ids() -> list[int]:
    raw = request.form.get("group_ids") or ""
    return [int(v) for v in raw.split(",") if v.strip().isdigit()]


def _bulk_response(result) -> str:  # noqa: ANN001
    """Re-render the table region plus an out-of-band toast reporting the
    outcome (§8.4: "toast reports 'Updated N findings'"). The request's current
    sort/filter/page query string is preserved by the client (see app.js), so
    this reflects the same view the user was already looking at. Undo is
    intentionally not implemented in this slice — see the commit notes."""
    if result.failed:
        msg = f"Updated {result.count} finding{'s' if result.count != 1 else ''} · {len(result.failed)} skipped"
    else:
        msg = f"Updated {result.count} finding{'s' if result.count != 1 else ''}"
    table_html = _render_findings(full_page=False)
    assert isinstance(table_html, str)
    toast_html = render_template("partials/toast.html", message=msg)
    return table_html + toast_html


@bp.post("/findings/bulk/transition")
@require_role(Capability.WORKFLOW_TRANSITION)
def bulk_finding_transition() -> Response | str:
    group_ids = _parse_group_ids()
    to_status = (request.form.get("to_status") or "").strip()
    # _bulk_response re-renders the table via its own session_scope, so the
    # mutation's session must be committed (the `with` block exited) first — a
    # nested, still-open session wouldn't see these uncommitted writes.
    with session_scope() as session:
        actor = current_user
        result = bulk_transition(session, group_ids, to_status, actor_id=actor.id)
    return _bulk_response(result)


@bp.post("/findings/bulk/assign")
@require_role(Capability.ASSIGN)
def bulk_finding_assign() -> Response | str:
    group_ids = _parse_group_ids()
    raw = (request.form.get("assignee_id") or "").strip()
    with session_scope() as session:
        actor = current_user
        assignee_id: int | None = actor.id if raw == "me" else (int(raw) if raw.isdigit() else None)
        result = bulk_assign(session, group_ids, assignee_id, actor_id=actor.id)
    return _bulk_response(result)


@bp.post("/findings/bulk/suppress")
@require_role(Capability.SUPPRESS)
def bulk_finding_suppress() -> Response | str:
    return _bulk_apply_exception("suppressed")


@bp.post("/findings/bulk/accept-risk")
@require_role(Capability.ACCEPT_RISK_CREATE)
def bulk_finding_accept_risk() -> Response | str:
    return _bulk_apply_exception("accepted_risk")


def _bulk_apply_exception(kind: str) -> Response | str:
    group_ids = _parse_group_ids()
    reason = request.form.get("reason") or ""
    expires_at = request.form.get("expires_at") or None
    with session_scope() as session:
        actor = current_user
        result = bulk_exception(
            session,
            group_ids,
            kind,
            reason=reason,
            actor_id=actor.id,
            actor_role=actor.role,
            expires_at=expires_at,
        )
    return _bulk_response(result)


@bp.get("/command-palette/search")
def palette_search() -> Response | str:
    """Findings results for the Cmd+K palette's search section (§8.5) — reuses
    ``query_findings`` exactly as the table does, just capped short."""
    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return ""
    with session_scope() as session:
        account = _current_account(session)
        if account is None:
            return ""
        page = query_findings(session, account.id, filters=FindingFilters(search=q), page_size=8)
        for row in page.rows:
            session.expunge(row)
        return render_template("partials/palette_results.html", rows=page.rows)


@dataclass(frozen=True)
class SinceLastScan:
    """The dashboard's "since last scan" strip (§5.4 / §8.9 entry point).

    Reuses the ``run_summary.new_count`` / ``resolved_count`` that ScanService
    has computed since Phase 0 rather than recomputing a diff — the strip is a
    teaser, and the full board is one click away. ``diff_href`` is None when
    there's no earlier run to compare against, which is also exactly when the
    counts themselves are NULL.
    """

    new_count: int
    resolved_count: int
    diff_href: str | None


def _since_last_scan(session, run) -> SinceLastScan | None:  # noqa: ANN001
    """None when this account has never been diffable (first ever scan), which
    the template reads as "don't render the strip at all"."""
    if run is None or run.summary is None:
        return None
    summary = run.summary
    if summary.new_count is None or summary.resolved_count is None:
        return None
    pair = default_diff_pair(session, run.account_id)
    return SinceLastScan(
        new_count=summary.new_count,
        resolved_count=summary.resolved_count,
        diff_href=url_for("web.runs_diff", a=pair[0], b=pair[1]) if pair else None,
    )


def _render_findings(*, full_page: bool, open_group: int | None = None) -> Response | str:
    sort = parse_sort(request.args.get("sort"))
    filters = parse_filters(request.args)
    page = _page_arg()
    columns = _selected_columns()

    with session_scope() as session:
        account = _current_account(session)
        if account is None:
            return render_template("empty_state.html", reason="no_data", columns=COLUMNS)

        expire_exceptions(session)  # re-surface anything whose expiry has passed
        result = query_findings(session, account.id, sort=sort, filters=filters, page=page)
        group_ids = [row.group_id for row in result.rows]
        assignees = assignee_names(session, group_ids)
        exceptions = active_exceptions(session, group_ids)
        # active_users() also drives the context menu's "Assign to…" submenu (§8.3);
        # (id, name) pairs are built here rather than in the template since Jinja
        # has no builtin `zip` filter.
        roster_json = [[u.id, u.display_name] for u in active_users(session)]
        # Resolved to plain fields before the expunges below, since it reads
        # run.summary (a lazy relationship) and the strip outlives the session.
        since = _since_last_scan(session, result.run) if full_page else None
        # Expunge so template access after the session closes doesn't lazy-load.
        for row in result.rows:
            session.expunge(row)
        for exc in exceptions.values():
            session.expunge(exc)
        if result.run is not None:
            session.expunge(result.run)
        session.expunge(account)

    ctx = {
        "account": account,
        "result": result,
        "assignees": assignees,
        "exceptions": exceptions,
        "roster_json": roster_json,
        "columns": COLUMNS,
        "selected_cols": columns,
        "sort_query": sort_to_query(sort),
        "sort_map": {s.key: s.desc for s in sort},
        "primary_sort": sort[0] if sort else None,
        "open_group": open_group,
        "since": since,
    }
    template = "findings.html" if full_page else "partials/findings_table.html"
    return render_template(template, **ctx)


@bp.get("/healthz")
def healthz() -> Response:
    from flask import jsonify

    return jsonify(status="ok")
