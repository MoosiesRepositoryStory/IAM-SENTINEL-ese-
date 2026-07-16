"""Web UI blueprint — Phase 1 Slice 1 (app shell + findings table read path).

Routes serve two shapes of the same data: full pages (with the shell) and, for
htmx requests, just the table partial so sort/filter/paginate swaps are cheap and
never reload the shell. The ``HX-Request`` header tells them apart.
"""

from __future__ import annotations

from typing import cast

from flask import Blueprint, Response, abort, redirect, render_template, request, url_for
from sqlalchemy import select

from app.db import session_scope
from app.domain.records import Thresholds
from app.models import Account, AppUser, Run
from app.models.base import now_iso
from app.services.account_service import list_accounts
from app.services.bulk_service import bulk_assign, bulk_exception, bulk_transition
from app.services.collaboration import CommentError, active_users, add_comment, assign
from app.services.connect_service import ConnectError, connect_account
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
from app.services.scan_service import ScanError, run_scan
from app.services.workflow_service import (
    STATUS_LABELS,
    InvalidTransition,
    available_actions,
    transition,
)

# Seeded demo roster (until auth in Phase 4): the current actor is the admin;
# the analysts make the assignee picker meaningful. (email, name, role).
_DEMO_ROSTER = [
    ("demo@iam-sentinel.local", "Demo Analyst", "admin"),
    ("priya@iam-sentinel.local", "Priya Nair", "analyst"),
    ("sam@iam-sentinel.local", "Sam Okafor", "analyst"),
]

bp = Blueprint("web", __name__)
# Single source of truth for the row-level context menu's "Change status" /
# "Suppress" / "Accept risk" items (§8.3) — the exact function the drawer
# footer already uses. Registered so findings_table.html can call it per row
# without a Python-side per-row loop.
bp.add_app_template_global(available_actions)

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


def _current_account(session) -> Account | None:  # noqa: ANN001
    """No account switcher exists yet (Slice 2) — "current" means the account
    behind the most recently *completed* run (whatever was just connected or
    re-scanned), falling back to the newest-created account if nothing has
    been scanned yet."""
    latest_run = session.scalar(
        select(Run).where(Run.status == "completed").order_by(Run.id.desc())
    )
    if latest_run is not None:
        return session.get(Account, latest_run.account_id)
    return session.scalar(select(Account).order_by(Account.id.desc()))


def _current_user(session) -> AppUser:  # noqa: ANN001
    """Until auth lands in Phase 4, actions are attributed to the seeded admin
    ("Demo Analyst") so the audit trail shows a real name and every transition
    (incl. accept-risk) is permitted. Also seeds the analyst roster so the
    assignee picker is populated."""
    admin: AppUser | None = None
    for email, name, role in _DEMO_ROSTER:
        user = session.scalar(select(AppUser).where(AppUser.email == email))
        if user is None:
            user = AppUser(
                email=email,
                display_name=name,
                password_hash="!",  # unusable; real auth arrives in Phase 4
                role=role,
                last_login_at=now_iso() if role == "admin" else None,
            )
            session.add(user)
            session.flush()
        if role == "admin":
            admin = user
    assert admin is not None
    return admin


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
def index() -> Response | str:
    """Dashboard placeholder for Slice 1 — redirects into the findings table."""
    with session_scope() as session:
        account = _current_account(session)
        run_count = session.scalar(select(Run.id).limit(1)) is not None
    if account is None or not run_count:
        return render_template("empty_state.html", reason="no_data", columns=COLUMNS)
    return _render_findings(full_page=True)


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
def connect_account_route() -> Response | str | tuple[str, int]:
    name = request.form.get("name", "")
    method = request.form.get("method", "demo")
    role_arn = request.form.get("role_arn", "")
    external_id = request.form.get("external_id", "")
    thresholds = _parse_thresholds()
    with session_scope() as session:
        actor = _current_user(session)
        try:
            connect_account(
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
            )
        except ConnectError as exc:
            rows = list_accounts(session)
            current = _current_account(session)
            current_id = current.id if current is not None else None
            _expunge_account_rows(session, rows)
            # Route.ARN/upload validation errors live on step 2's fields; name and
            # scan-execution errors are only visible on step 3 — reopen wherever the
            # bad field actually is rather than always landing on step 3.
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
                    "name": name, "method": method,
                    "role_arn": role_arn, "external_id": external_id,
                },
            ), 400
    return cast(Response, redirect(url_for("web.findings")))


@bp.post("/accounts/<int:account_id>/scan")
def rescan_account(account_id: int) -> Response | str | tuple[str, int]:
    """Re-scan an existing account with its saved thresholds (§5.3 step 5's
    "Scan now" — this is what makes ``_current_account`` point at it again)."""
    with session_scope() as session:
        account = session.get(Account, account_id)
        if account is None:
            abort(404)
        actor = _current_user(session)
        thresholds = Thresholds.from_dict(account.source_config or {})
        try:
            run_scan(session, account.id, thresholds=thresholds, triggered_by=actor.id)
        except ScanError as exc:
            rows = list_accounts(session)
            current = _current_account(session)
            current_id = current.id if current is not None else None
            _expunge_account_rows(session, rows)
            return render_template(
                "accounts.html",
                rows=rows,
                current_account_id=current_id,
                default_thresholds=Thresholds().to_dict(),
                error=f"Re-scan failed: {exc}",
            ), 400
    return cast(Response, redirect(url_for("web.findings")))


def _render_drawer(session, group_id: int, **extra) -> str:  # noqa: ANN001, ANN003
    """Render the drawer partial for ``group_id`` (404s if missing). ``extra``
    passes flags like ``oob_status`` / ``oob_assignee`` / ``error``."""
    detail = get_finding_detail(session, group_id)
    if detail is None:
        abort(404)
    return render_template(
        "partials/finding_drawer.html",
        d=detail,
        status_labels=STATUS_LABELS,
        users=active_users(session),
        **extra,
    )


@bp.get("/findings/<int:group_id>")
def finding_drawer(group_id: int) -> Response | str:
    """Finding detail drawer (§8.8). htmx → the drawer partial; a direct visit
    (deep link, §8.11) → the full findings page with the drawer auto-opened.

    Optional ``?tab=`` opens on a specific tab (used by the context menu's "View
    evidence" / "Add comment…" items) and ``?action=suppressed|accepted_risk`` also
    pre-reveals that exception form (used by "Suppress finding…" / "Accept
    risk…") — both reuse markup/routes already built in 2a-2c, just pre-seeded.
    """
    tab = request.args.get("tab")
    action = request.args.get("action")
    if not _is_htmx():
        return _render_findings(full_page=True, open_group=group_id)
    with session_scope() as session:
        _current_user(session)  # seed the roster so the assignee picker is populated
        expire_exceptions(session)  # re-surface anything whose expiry has passed
        return _render_drawer(session, group_id, focus_tab=tab, open_action=action)


@bp.post("/findings/<int:group_id>/transition")
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
        actor = _current_user(session)
        try:
            if to_status == "open" and detail.group.current_status in EXCEPTION_STATUSES:
                revoke_exception(session, detail.group, actor_id=actor.id, note=note or "Exception revoked")
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
        actor = _current_user(session)
        try:
            create_exception(
                session, detail.group, kind=kind, reason=reason, actor_id=actor.id,
                expires_at=expires_at,
            )
        except InvalidTransition as exc:
            return _render_drawer(session, group_id, error=str(exc)), 409
        except ExceptionError as exc:
            return _render_drawer(session, group_id, error=str(exc)), 400
        return _render_drawer(session, group_id, oob_status=True)


@bp.post("/findings/<int:group_id>/suppress")
def finding_suppress(group_id: int) -> Response | str | tuple[str, int]:
    """Suppress a finding: requires a reason, no expiry (§7.4 — suppression is
    "don't show me this", not time-boxed)."""
    return _apply_exception(group_id, "suppressed")


@bp.post("/findings/<int:group_id>/accept-risk")
def finding_accept_risk(group_id: int) -> Response | str | tuple[str, int]:
    """Accept risk on a finding: requires a reason, optional expiry after which
    it auto-reopens (§7.4)."""
    return _apply_exception(group_id, "accepted_risk")


@bp.post("/findings/<int:group_id>/comment")
def finding_comment(group_id: int) -> Response | str | tuple[str, int]:
    """Add a comment and return the refreshed drawer (Activity tab focused)."""
    body = request.form.get("body") or ""
    with session_scope() as session:
        detail = get_finding_detail(session, group_id)
        if detail is None:
            abort(404)
        author = _current_user(session)
        try:
            add_comment(session, detail.group, author_id=author.id, body=body)
        except CommentError as exc:
            return _render_drawer(session, group_id, error=str(exc), focus_tab="activity"), 400
        return _render_drawer(session, group_id, focus_tab="activity")


@bp.post("/findings/<int:group_id>/assign")
def finding_assign(group_id: int) -> Response | str:
    """Assign/unassign the finding and return the refreshed drawer plus an
    out-of-band swap for the table row's assignee cell. ``assignee_id`` may be
    'me', '' / 'none' (unassign), or a user id."""
    raw = (request.form.get("assignee_id") or "").strip()
    with session_scope() as session:
        detail = get_finding_detail(session, group_id)
        if detail is None:
            abort(404)
        actor = _current_user(session)
        if raw == "me":
            assignee_id: int | None = actor.id
        elif raw in {"", "none"}:
            assignee_id = None
        else:
            assignee_id = int(raw) if raw.isdigit() else None
        assign(session, detail.group, assignee_id=assignee_id, actor_id=actor.id)
        return _render_drawer(session, group_id, oob_assignee=True)


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
def bulk_finding_transition() -> Response | str:
    group_ids = _parse_group_ids()
    to_status = (request.form.get("to_status") or "").strip()
    # _bulk_response re-renders the table via its own session_scope, so the
    # mutation's session must be committed (the `with` block exited) first — a
    # nested, still-open session wouldn't see these uncommitted writes.
    with session_scope() as session:
        actor = _current_user(session)
        result = bulk_transition(session, group_ids, to_status, actor_id=actor.id)
    return _bulk_response(result)


@bp.post("/findings/bulk/assign")
def bulk_finding_assign() -> Response | str:
    group_ids = _parse_group_ids()
    raw = (request.form.get("assignee_id") or "").strip()
    with session_scope() as session:
        actor = _current_user(session)
        assignee_id: int | None = actor.id if raw == "me" else (int(raw) if raw.isdigit() else None)
        result = bulk_assign(session, group_ids, assignee_id, actor_id=actor.id)
    return _bulk_response(result)


@bp.post("/findings/bulk/suppress")
def bulk_finding_suppress() -> Response | str:
    return _bulk_apply_exception("suppressed")


@bp.post("/findings/bulk/accept-risk")
def bulk_finding_accept_risk() -> Response | str:
    return _bulk_apply_exception("accepted_risk")


def _bulk_apply_exception(kind: str) -> Response | str:
    group_ids = _parse_group_ids()
    reason = request.form.get("reason") or ""
    expires_at = request.form.get("expires_at") or None
    with session_scope() as session:
        actor = _current_user(session)
        result = bulk_exception(
            session, group_ids, kind, reason=reason, actor_id=actor.id, expires_at=expires_at
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
        page = query_findings(
            session, account.id, filters=FindingFilters(search=q), page_size=8
        )
        for row in page.rows:
            session.expunge(row)
        return render_template("partials/palette_results.html", rows=page.rows)


def _render_findings(*, full_page: bool, open_group: int | None = None) -> Response | str:
    sort = parse_sort(request.args.get("sort"))
    filters = parse_filters(request.args)
    page = _page_arg()
    columns = _selected_columns()

    with session_scope() as session:
        account = _current_account(session)
        if account is None:
            return render_template("empty_state.html", reason="no_data", columns=COLUMNS)

        _current_user(session)  # seed the roster so "Assign to…" isn't empty on first load
        expire_exceptions(session)  # re-surface anything whose expiry has passed
        result = query_findings(session, account.id, sort=sort, filters=filters, page=page)
        group_ids = [row.group_id for row in result.rows]
        assignees = assignee_names(session, group_ids)
        exceptions = active_exceptions(session, group_ids)
        # active_users() also drives the context menu's "Assign to…" submenu (§8.3);
        # (id, name) pairs are built here rather than in the template since Jinja
        # has no builtin `zip` filter.
        roster_json = [[u.id, u.display_name] for u in active_users(session)]
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
    }
    template = "findings.html" if full_page else "partials/findings_table.html"
    return render_template(template, **ctx)


@bp.get("/healthz")
def healthz() -> Response:
    from flask import jsonify

    return jsonify(status="ok")
