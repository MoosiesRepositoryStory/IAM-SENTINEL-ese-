"""Bulk finding actions for the multi-select context menu (§8.4).

Every function here is a thin loop over the *exact* single-finding functions
already built in 2a/2b/2c (``workflow_service.transition``,
``collaboration.assign``, ``exception_service.create_exception``) — no
validation or state-machine rule is duplicated. A bad item (e.g. one row in the
selection is already resolved) fails that item without aborting the batch,
matching how a real bulk operation should behave: report partial success rather
than an all-or-nothing failure over an unrelated row.

Per §8.4, all bulk mutations already write their normal per-group
``finding_status_history`` rows (via the wrapped single-item functions); this
module additionally writes *one* summarizing ``audit_event`` per batch so a
bulk action is visible as a single event, not just N scattered ones.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.models import AuditEvent, FindingGroup
from app.services.collaboration import assign
from app.services.exception_service import ExceptionError, create_exception
from app.services.workflow_service import InvalidTransition, transition


@dataclass
class BulkResult:
    action: str
    succeeded: list[int] = field(default_factory=list)
    failed: list[tuple[int, str]] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.succeeded)


def _record_batch_event(session: Session, actor_id: int | None, action: str, result: BulkResult, **meta: object) -> None:
    if not result.succeeded:
        return
    session.add(
        AuditEvent(
            actor_id=actor_id,
            action=f"bulk_{action}",
            target=None,
            event_metadata={"group_ids": result.succeeded, "count": result.count, **meta},
        )
    )
    session.flush()


def bulk_transition(
    session: Session, group_ids: list[int], to_status: str, *, actor_id: int | None, note: str | None = None
) -> BulkResult:
    result = BulkResult(action="transition")
    for gid in group_ids:
        group = session.get(FindingGroup, gid)
        if group is None:
            result.failed.append((gid, "not found"))
            continue
        try:
            transition(session, group, to_status, actor_id=actor_id, note=note)
        except InvalidTransition as exc:
            result.failed.append((gid, str(exc)))
        else:
            result.succeeded.append(gid)
    _record_batch_event(session, actor_id, "transition", result, to_status=to_status)
    return result


def bulk_assign(
    session: Session, group_ids: list[int], assignee_id: int | None, *, actor_id: int | None
) -> BulkResult:
    result = BulkResult(action="assign")
    for gid in group_ids:
        group = session.get(FindingGroup, gid)
        if group is None:
            result.failed.append((gid, "not found"))
            continue
        assign(session, group, assignee_id=assignee_id, actor_id=actor_id)
        result.succeeded.append(gid)
    _record_batch_event(session, actor_id, "assign", result, assignee_id=assignee_id)
    return result


def bulk_exception(
    session: Session,
    group_ids: list[int],
    kind: str,
    *,
    reason: str,
    actor_id: int,
    expires_at: str | None = None,
) -> BulkResult:
    """Suppress or accept-risk every group in ``group_ids`` with one shared
    reason (+ optional expiry for accepted_risk), per §8.4's "single reason +
    expiry applied to all". ``create_exception`` re-validates the reason/expiry
    on every call (cheap, and it's the single source of truth for that rule) —
    a bad reason/date is therefore identically rejected for every item, so in
    practice nothing in the batch succeeds, without needing a separate
    up-front check here."""
    result = BulkResult(action=kind)
    for gid in group_ids:
        group = session.get(FindingGroup, gid)
        if group is None:
            result.failed.append((gid, "not found"))
            continue
        try:
            create_exception(
                session, group, kind=kind, reason=reason, actor_id=actor_id, expires_at=expires_at
            )
        except (InvalidTransition, ExceptionError) as exc:
            result.failed.append((gid, str(exc)))
        else:
            result.succeeded.append(gid)
    _record_batch_event(session, actor_id, kind, result, reason=reason, expires_at=expires_at)
    return result
