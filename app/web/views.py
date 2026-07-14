"""Web UI blueprint — Phase 1 Slice 1 (app shell + findings table read path).

Routes serve two shapes of the same data: full pages (with the shell) and, for
htmx requests, just the table partial so sort/filter/paginate swaps are cheap and
never reload the shell. The ``HX-Request`` header tells them apart.
"""

from __future__ import annotations

from flask import Blueprint, Response, render_template, request
from sqlalchemy import select

from app.db import session_scope
from app.models import Account, Run
from app.services.finding_query import (
    parse_filters,
    parse_sort,
    query_findings,
    sort_to_query,
)

bp = Blueprint("web", __name__)

# Column definitions drive both the header row and the "Columns" menu (§8.2).
# ``key`` matches finding_query._SORTABLE where sortable; ``default`` = shown.
COLUMNS: list[dict[str, str | bool]] = [
    {"key": "risk", "label": "Risk", "sortable": True, "default": True},
    {"key": "severity", "label": "Severity", "sortable": True, "default": True},
    {"key": "status", "label": "Status", "sortable": True, "default": True},
    {"key": "title", "label": "Title", "sortable": True, "default": True},
    {"key": "principal", "label": "Principal", "sortable": True, "default": True},
    {"key": "category", "label": "Category", "sortable": True, "default": True},
    {"key": "compliance", "label": "Compliance", "sortable": False, "default": True},
    {"key": "last_seen", "label": "Last seen", "sortable": True, "default": True},
    {"key": "first_seen", "label": "First seen", "sortable": True, "default": False},
    {"key": "check", "label": "Check ID", "sortable": True, "default": False},
]
_DEFAULT_COLS: list[str] = [str(c["key"]) for c in COLUMNS if c["default"]]


def _current_account(session) -> Account | None:  # noqa: ANN001
    """Slice 1 has no account switcher yet — use the most recently created."""
    return session.scalar(select(Account).order_by(Account.id.desc()))


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


def _is_htmx() -> bool:
    return request.headers.get("HX-Request") == "true"


def _render_findings(*, full_page: bool) -> Response | str:
    sort = parse_sort(request.args.get("sort"))
    filters = parse_filters(request.args)
    page = _page_arg()
    columns = _selected_columns()

    with session_scope() as session:
        account = _current_account(session)
        if account is None:
            return render_template("empty_state.html", reason="no_data", columns=COLUMNS)

        result = query_findings(session, account.id, sort=sort, filters=filters, page=page)
        # Expunge so template access after the session closes doesn't lazy-load.
        for row in result.rows:
            session.expunge(row)
        if result.run is not None:
            session.expunge(result.run)
        session.expunge(account)

    ctx = {
        "account": account,
        "result": result,
        "columns": COLUMNS,
        "selected_cols": columns,
        "sort_query": sort_to_query(sort),
        "sort_map": {s.key: s.desc for s in sort},
        "primary_sort": sort[0] if sort else None,
    }
    template = "findings.html" if full_page else "partials/findings_table.html"
    return render_template(template, **ctx)


@bp.get("/healthz")
def healthz() -> Response:
    from flask import jsonify

    return jsonify(status="ok")
