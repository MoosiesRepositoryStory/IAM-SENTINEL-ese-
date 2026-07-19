"""Assembles everything the finding detail drawer (§8.8) needs for one group.

A ``finding_group`` is the durable unit (status, assignee, first/last-seen); the
per-run ``finding`` holds the evidence/severity/recommendation snapshot. The
drawer shows the *latest* snapshot plus the group's unified Activity timeline —
status changes + comments + assignment events, chronologically merged (§8.8).
First/last-seen dates resolve through the group's ``first_seen_run`` /
``last_seen_run``.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.timeutil import days_since, parse_dt
from app.models import (
    AppUser,
    Finding,
    FindingComment,
    FindingGroup,
    FindingStatusHistory,
    Run,
)
from app.services.collaboration import assignment_events
from app.services.exception_service import active_exception
from app.services.workflow_service import available_actions


@dataclass(frozen=True)
class AuditEntry:
    """A status-history row (kept for callers that only want status changes)."""

    from_status: str | None
    to_status: str
    actor_name: str
    note: str | None
    at: str  # ISO timestamp


@dataclass(frozen=True)
class ActivityItem:
    """One entry in the unified Activity timeline."""

    kind: str  # 'status' | 'comment' | 'assignment'
    at: str
    actor_name: str
    # status
    from_status: str | None = None
    to_status: str | None = None
    note: str | None = None
    # comment
    body: str | None = None
    # assignment
    assign_to: str | None = None  # None => unassigned


@dataclass(frozen=True)
class ExceptionInfo:
    """The group's current active exception (§7.4) — reason/expiry only, not
    history; the create/revoke/expire events themselves show up as 'status' kind
    entries in ``activity`` since they go through the same status transitions."""

    kind: str
    reason: str
    expires_at: str | None  # ISO date (YYYY-MM-DD) or None (no expiry)
    created_by_name: str
    created_at: str


@dataclass
class FindingDetail:
    group: FindingGroup
    finding: Finding
    history: list[AuditEntry]
    activity: list[ActivityItem]
    assignee_name: str | None
    exception: ExceptionInfo | None
    first_seen: str | None  # ISO date (YYYY-MM-DD) or None
    last_seen: str | None
    age_days: int | None
    actions: list[tuple[str, str]]  # available status transitions (to, label)


def _run_date(session: Session, run_id: int | None) -> str | None:
    if run_id is None:
        return None
    created = session.scalar(select(Run.created_at).where(Run.id == run_id))
    return created[:10] if created else None


def _name_map(session: Session, ids: set[int]) -> dict[int, str]:
    if not ids:
        return {}
    return {
        row.id: row.display_name
        for row in session.execute(
            select(AppUser.id, AppUser.display_name).where(AppUser.id.in_(ids))
        )
    }


def get_finding_detail(
    session: Session, group_id: int, *, actor_role: str | None = None
) -> FindingDetail | None:
    """Return the drawer payload for ``group_id``, or ``None`` if it doesn't
    exist. ``actor_role`` is forwarded to ``available_actions`` so the drawer
    footer only offers transitions the caller's role permits (§10.2) —
    ``None`` (the default) offers every transition unfiltered, matching
    ``available_actions``'s own convention for internal/test callers."""
    group = session.get(FindingGroup, group_id)
    if group is None:
        return None

    finding = session.scalar(
        select(Finding)
        .where(Finding.group_id == group.id, Finding.run_id == group.last_seen_run)
        .limit(1)
    )
    if finding is None:  # fall back to the most recent snapshot in any run
        finding = session.scalar(
            select(Finding).where(Finding.group_id == group.id).order_by(Finding.id.desc()).limit(1)
        )
    if finding is None:
        return None

    status_rows = list(
        session.scalars(
            select(FindingStatusHistory)
            .where(FindingStatusHistory.group_id == group.id)
            .order_by(FindingStatusHistory.id.asc())
        )
    )
    comments = list(
        session.scalars(
            select(FindingComment)
            .where(FindingComment.group_id == group.id)
            .order_by(FindingComment.id.asc())
        )
    )
    assignments = assignment_events(session, group.id)
    exception = active_exception(session, group.id)

    actor_ids: set[int] = {r.actor_id for r in status_rows if r.actor_id is not None}
    actor_ids |= {c.author_id for c in comments}
    actor_ids |= {a.actor_id for a in assignments if a.actor_id is not None}
    if exception is not None:
        actor_ids.add(exception.created_by)
    names = _name_map(session, actor_ids)

    history = [
        AuditEntry(
            from_status=r.from_status,
            to_status=r.to_status,
            actor_name=names.get(r.actor_id, "System") if r.actor_id else "System",
            note=r.note,
            at=r.created_at,
        )
        for r in status_rows
    ]

    activity: list[ActivityItem] = [
        ActivityItem(
            kind="status",
            at=r.created_at,
            actor_name=names.get(r.actor_id, "System") if r.actor_id else "System",
            from_status=r.from_status,
            to_status=r.to_status,
            note=r.note,
        )
        for r in status_rows
    ]
    activity += [
        ActivityItem(
            kind="comment",
            at=c.created_at,
            actor_name=names.get(c.author_id, "Unknown"),
            body=c.body,
        )
        for c in comments
    ]
    activity += [
        ActivityItem(
            kind="assignment",
            at=a.created_at,
            actor_name=names.get(a.actor_id, "System") if a.actor_id else "System",
            assign_to=(a.event_metadata or {}).get("to_name"),
        )
        for a in assignments
    ]
    # Chronological; 'status' sorts before same-instant comment/assignment so a
    # "Detected" origin always leads.
    _kind_rank = {"status": 0, "assignment": 1, "comment": 2}
    activity.sort(key=lambda i: (i.at, _kind_rank.get(i.kind, 9)))

    exception_info = None
    if exception is not None:
        exception_info = ExceptionInfo(
            kind=exception.kind,
            reason=exception.reason,
            expires_at=exception.expires_at,
            created_by_name=names.get(exception.created_by, "Unknown"),
            created_at=exception.created_at,
        )

    return FindingDetail(
        group=group,
        finding=finding,
        history=history,
        activity=activity,
        assignee_name=names.get(group.assignee_id) if group.assignee_id else None,
        exception=exception_info,
        first_seen=_run_date(session, group.first_seen_run),
        last_seen=_run_date(session, group.last_seen_run),
        age_days=days_since(parse_dt(_run_date(session, group.first_seen_run))),
        actions=available_actions(group.current_status, actor_role),
    )
