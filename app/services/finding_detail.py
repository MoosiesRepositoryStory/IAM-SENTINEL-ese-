"""Assembles everything the finding detail drawer (§8.8) needs for one group.

A ``finding_group`` is the durable unit (status, assignee, first/last-seen); the
per-run ``finding`` holds the evidence/severity/recommendation snapshot. The
drawer shows the *latest* snapshot plus the group's audit trail. First/last-seen
dates resolve through the group's ``first_seen_run`` / ``last_seen_run``.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.timeutil import days_since, parse_dt
from app.models import AppUser, Finding, FindingGroup, FindingStatusHistory, Run
from app.services.workflow_service import available_actions


@dataclass(frozen=True)
class AuditEntry:
    from_status: str | None
    to_status: str
    actor_name: str
    note: str | None
    at: str  # ISO timestamp


@dataclass
class FindingDetail:
    group: FindingGroup
    finding: Finding
    history: list[AuditEntry]
    first_seen: str | None  # ISO date (YYYY-MM-DD) or None
    last_seen: str | None
    age_days: int | None
    actions: list[tuple[str, str]]  # available status transitions (to, label)


def _run_date(session: Session, run_id: int | None) -> str | None:
    if run_id is None:
        return None
    created = session.scalar(select(Run.created_at).where(Run.id == run_id))
    return created[:10] if created else None


def get_finding_detail(session: Session, group_id: int) -> FindingDetail | None:
    """Return the drawer payload for ``group_id``, or ``None`` if it doesn't exist."""
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

    rows = list(
        session.scalars(
            select(FindingStatusHistory)
            .where(FindingStatusHistory.group_id == group.id)
            .order_by(FindingStatusHistory.id.asc())
        )
    )
    actor_ids = {r.actor_id for r in rows if r.actor_id is not None}
    names: dict[int, str] = {}
    if actor_ids:
        names = {
            row.id: row.display_name
            for row in session.execute(
                select(AppUser.id, AppUser.display_name).where(AppUser.id.in_(actor_ids))
            )
        }

    history = [
        AuditEntry(
            from_status=r.from_status,
            to_status=r.to_status,
            actor_name=names.get(r.actor_id, "System") if r.actor_id else "System",
            note=r.note,
            at=r.created_at,
        )
        for r in rows
    ]

    last_seen = _run_date(session, group.last_seen_run)
    return FindingDetail(
        group=group,
        finding=finding,
        history=history,
        first_seen=_run_date(session, group.first_seen_run),
        last_seen=last_seen,
        age_days=days_since(parse_dt(_run_date(session, group.first_seen_run))),
        actions=available_actions(group.current_status),
    )
