"""Read-side query for the findings table (§8.2).

Phase 1 Slice 1 renders the *latest completed run* for an account. The table's
sort/filter/column state is fully encoded in URL query params so every view is
shareable and htmx-refreshable; this module parses that state and returns a
paginated, sorted, filtered slice plus the facet counts the filter bar needs.

Sorting and filtering run in SQL where the column maps directly to a DB column.
Severity is the one exception: its natural order is by ``rank`` (LOW<...<CRITICAL),
not alphabetical, so we sort it via a CASE expression rather than by the string.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from sqlalchemy import Select, case, func, or_, select
from sqlalchemy.orm import Session

from app.domain.enums import Category, Severity, Status
from app.models import AppUser, Finding, FindingGroup, Run

# Columns the table may sort by, mapped to their ORM sort expression. Anything
# not in here is rejected and falls back to the default sort.
_SEVERITY_ORDER = case(
    {s.value: s.rank for s in Severity},
    value=Finding.severity,
    else_=-1,
)
_SORTABLE: dict[str, Any] = {
    "risk": Finding.risk_score,
    "severity": _SEVERITY_ORDER,
    "status": Finding.status,
    "title": func.lower(Finding.title),
    "principal": Finding.principal_uid,
    "category": Finding.category,
    "check": Finding.check_id,
    # Findings are per-run snapshots, so both timestamps are this scan's date.
    # True cross-run first-seen (via FindingGroup.first_seen_run) surfaces with the
    # Phase 2 run-diff view; Slice 1 shows the scan date for both.
    "last_seen": Finding.created_at,
    "first_seen": Finding.created_at,
}
_DEFAULT_SORT = [("risk", True), ("severity", True)]  # (key, descending)

PAGE_SIZE = 50


@dataclass(frozen=True)
class SortKey:
    key: str
    desc: bool


@dataclass
class FindingFilters:
    """Parsed, validated filter state. All facets AND together; within a facet
    the selected values OR together (§8.2)."""

    severity: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    category: list[str] = field(default_factory=list)
    check: list[str] = field(default_factory=list)
    search: str = ""

    @property
    def active(self) -> bool:
        return bool(self.severity or self.status or self.category or self.check or self.search)


@dataclass
class FindingsPage:
    run: Run | None
    rows: list[Finding]
    total: int  # rows matching the filter (not the page size)
    page: int
    page_size: int
    sort: list[SortKey]
    filters: FindingFilters
    facets: dict[str, dict[str, int]]  # facet -> value -> count (over the run, pre-filter)

    @property
    def pages(self) -> int:
        return max(1, -(-self.total // self.page_size))  # ceil

    @property
    def start_index(self) -> int:
        return 0 if self.total == 0 else (self.page - 1) * self.page_size + 1

    @property
    def end_index(self) -> int:
        return min(self.page * self.page_size, self.total)


def _valid_values(enum_cls: type[Enum], raw: list[str]) -> list[str]:
    allowed = {str(m.value) for m in enum_cls}
    return [v for v in raw if v in allowed]


def parse_sort(raw: str | None) -> list[SortKey]:
    """Parse ``?sort=-risk,severity`` -> [SortKey(risk, desc), SortKey(severity, asc)]."""
    if not raw:
        return [SortKey(k, d) for k, d in _DEFAULT_SORT]
    keys: list[SortKey] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        desc = token.startswith("-")
        name = token.lstrip("+-")
        if name in _SORTABLE:
            keys.append(SortKey(name, desc))
    return keys or [SortKey(k, d) for k, d in _DEFAULT_SORT]


def sort_to_query(sort: list[SortKey]) -> str:
    """Inverse of :func:`parse_sort` — for building header links."""
    return ",".join(f"{'-' if s.desc else ''}{s.key}" for s in sort)


def parse_filters(args: dict[str, list[str]] | Any) -> FindingFilters:
    """Build filters from a request's multi-dict. Accepts anything with
    ``getlist``/``get`` (Werkzeug MultiDict) or a plain ``{key: [values]}`` dict."""

    def getlist(key: str) -> list[str]:
        if hasattr(args, "getlist"):
            return [v for v in args.getlist(key) if v]
        return [v for v in args.get(key, []) if v]

    def getone(key: str) -> str:
        if hasattr(args, "get") and not isinstance(args, dict):
            return (args.get(key) or "").strip()
        vals = args.get(key, []) if isinstance(args, dict) else []
        return (vals[0] if vals else "").strip()

    return FindingFilters(
        severity=_valid_values(Severity, getlist("severity")),
        status=_valid_values(Status, getlist("status")),
        category=_valid_values(Category, getlist("category")),
        check=getlist("check"),
        search=getone("q"),
    )


def latest_run(session: Session, account_id: int) -> Run | None:
    return session.scalar(
        select(Run)
        .where(Run.account_id == account_id, Run.status == "completed")
        .order_by(Run.id.desc())
    )


def _apply_filters(stmt: Select[Any], f: FindingFilters) -> Select[Any]:
    if f.severity:
        stmt = stmt.where(Finding.severity.in_(f.severity))
    if f.status:
        stmt = stmt.where(Finding.status.in_(f.status))
    if f.category:
        stmt = stmt.where(Finding.category.in_(f.category))
    if f.check:
        stmt = stmt.where(Finding.check_id.in_(f.check))
    if f.search:
        like = f"%{f.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Finding.title).like(like),
                func.lower(func.coalesce(Finding.principal_uid, "")).like(like),
            )
        )
    return stmt


def _facet_counts(session: Session, run_id: int, column: Any) -> dict[str, int]:
    rows = session.execute(
        select(column, func.count()).where(Finding.run_id == run_id).group_by(column)
    ).all()
    return {str(value): count for value, count in rows if value is not None}


def query_findings(
    session: Session,
    account_id: int,
    *,
    sort: list[SortKey] | None = None,
    filters: FindingFilters | None = None,
    page: int = 1,
    page_size: int = PAGE_SIZE,
    offset: int | None = None,
) -> FindingsPage:
    """Return one page of findings for the account's latest completed run.

    ``offset``, when given, overrides the ``(page - 1) * page_size``
    computation with an exact row offset — the API read surface (Phase 4
    Slice 4a) uses arbitrary ``?limit=&offset=`` pagination rather than the
    HTML app's fixed-page-size UI, and this is the same underlying query
    either way. ``page`` in the returned :class:`FindingsPage` becomes
    advisory in that case (``offset // page_size + 1``) — callers using raw
    offset pagination should read ``total``/``rows`` directly rather than
    ``.pages``.
    """
    sort = sort or [SortKey(k, d) for k, d in _DEFAULT_SORT]
    filters = filters or FindingFilters()
    page = max(1, page)

    run = latest_run(session, account_id)
    if run is None:
        return FindingsPage(
            run=None,
            rows=[],
            total=0,
            page=1,
            page_size=page_size,
            sort=sort,
            filters=filters,
            facets={},
        )

    base = select(Finding).where(Finding.run_id == run.id)
    filtered = _apply_filters(base, filters)

    total = (
        session.scalar(
            _apply_filters(
                select(func.count()).select_from(Finding).where(Finding.run_id == run.id),
                filters,
            )
        )
        or 0
    )

    order_cols = []
    for s in sort:
        col = _SORTABLE.get(s.key)
        if col is None:
            continue
        order_cols.append(col.desc() if s.desc else col.asc())
    order_cols.append(Finding.id.asc())  # stable tiebreak

    effective_offset = offset if offset is not None else (page - 1) * page_size
    if offset is not None:
        page = offset // page_size + 1 if page_size else 1

    rows = list(
        session.scalars(filtered.order_by(*order_cols).offset(effective_offset).limit(page_size))
    )

    facets = {
        "severity": _facet_counts(session, run.id, Finding.severity),
        "status": _facet_counts(session, run.id, Finding.status),
        "category": _facet_counts(session, run.id, Finding.category),
    }

    return FindingsPage(
        run=run,
        rows=rows,
        total=total,
        page=page,
        page_size=page_size,
        sort=sort,
        filters=filters,
        facets=facets,
    )


# ---------------------------------------------------------------------------
# Fuzzy fallback (§8.5 command palette) — only reached when the exact/
# substring search above (FindingFilters.search's SQL LIKE) returns zero
# results, so a typo doesn't just dead-end at "no findings match".

# Defensive cap on how many rows the Python-side matching pass considers —
# this app's real scale (a demo/portfolio moto org, or a file-uploaded org)
# is nowhere near this today, but the cap keeps a pathologically large
# account from ever making one keystroke slow. Empirically timed against a
# realistic multi-word query at exactly this many synthetic candidate rows:
# ~55-65ms worst case (SequenceMatcher.quick_ratio() pre-filtering the
# expensive ratio() call, per the stdlib's own documented pattern for
# comparing one sequence against many) — comfortably inside the 200ms
# debounce this already runs behind, even before counting network/DB time.
_FUZZY_CANDIDATE_CAP = 500
_FUZZY_CUTOFF = 0.6
_TOKEN_RE = re.compile(r"[^a-z0-9]+")


def _tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.split(text.lower()) if t]


def fuzzy_search_findings(session: Session, account_id: int, query: str, *, limit: int = 8) -> list[Finding]:
    """Typo-tolerant fallback over the SAME candidate corpus the exact search
    uses (``Finding.title`` + ``Finding.principal_uid``, scoped to the
    account's latest completed run) — Python-side ``difflib`` matching, not a
    DB-specific fuzzy extension (e.g. Postgres's ``pg_trgm``), so it behaves
    identically on SQLite (dev/CI) and Postgres (the live deploy).

    Per-candidate score is the average, over each query token, of that
    token's best ``SequenceMatcher.ratio()`` against any one of the
    candidate's own tokens — scored at the token level (not the whole
    title/principal string at once) so a short, misspelled query fragment
    isn't penalized for the surrounding words in a long title the way a
    whole-string ratio would be. Results are capped at ``limit`` (matching
    the exact path's page size) and sorted best-match-first.
    """
    run = latest_run(session, account_id)
    if run is None:
        return []
    query_tokens = _tokenize(query)
    if not query_tokens:
        return []

    candidates = list(
        session.scalars(select(Finding).where(Finding.run_id == run.id).limit(_FUZZY_CANDIDATE_CAP))
    )

    # One SequenceMatcher per query token, reused across every candidate token
    # via set_seq2() — the stdlib's own recommended usage for comparing one
    # sequence against many, and what makes quick_ratio()'s cheap upper-bound
    # pre-filter (skip the expensive real comparison whenever it can't
    # possibly beat the best score found so far) actually pay off.
    matchers = [difflib.SequenceMatcher(None, qt) for qt in query_tokens]

    scored: list[tuple[float, Finding]] = []
    for finding in candidates:
        candidate_tokens = _tokenize(f"{finding.title} {finding.principal_uid or ''}")
        if not candidate_tokens:
            continue
        total = 0.0
        for matcher in matchers:
            best = 0.0
            for tok in candidate_tokens:
                matcher.set_seq2(tok)
                if matcher.quick_ratio() <= best:
                    continue
                ratio = matcher.ratio()
                if ratio > best:
                    best = ratio
            total += best
        score = total / len(query_tokens)
        if score >= _FUZZY_CUTOFF:
            scored.append((score, finding))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [finding for _, finding in scored[:limit]]


def assignee_names(session: Session, group_ids: list[int]) -> dict[int, str]:
    """Map group id -> assignee display name for the groups that have one, so the
    table's Assignee column can render without a per-row lookup."""
    if not group_ids:
        return {}
    rows = session.execute(
        select(FindingGroup.id, AppUser.display_name)
        .join(AppUser, FindingGroup.assignee_id == AppUser.id)
        .where(FindingGroup.id.in_(group_ids))
    )
    return {row.id: row.display_name for row in rows}


def group_meta(session: Session, group_ids: list[int]) -> dict[int, FindingGroup]:
    """Fetch the durable FindingGroup rows for a set of findings (status/assignee/
    first-last-seen live on the group, not the per-run Finding)."""
    if not group_ids:
        return {}
    groups = session.scalars(select(FindingGroup).where(FindingGroup.id.in_(group_ids)))
    return {g.id: g for g in groups}
