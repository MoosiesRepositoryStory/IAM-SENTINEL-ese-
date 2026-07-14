"""Suppression & accepted-risk exceptions, with expiry-driven re-surfacing (§7.4).

Suppressing or accepting risk on a finding is a status transition (§7.1) *plus* a
``finding_exception`` row recording why and, for accepted-risk, for how long.
Revoking (the "Reopen" action from either state) closes the exception and moves
the group back to ``open`` — the spec's own §7.1 diagram already routes every
exit from an exception state to ``open`` (manual revoke *and* auto-expiry both
land there), so re-surfacing reuses that same state rather than inventing a new
"needs re-review" status the rest of the state machine (and the drawer's action
buttons) wouldn't know about.

Both paths go through ``workflow_service.transition``, so creating, revoking, or
auto-expiring an exception all show up as ordinary status-history entries in the
drawer's unified Activity tab — ``finding_exception`` itself only carries the
*current* reason/expiry, not history.

Scope note (Slice 2c): §7.4 assigns automatic expiry to "a daily APScheduler
job". Phase 2 is where a real background scheduler (APScheduler/RQ) gets wired
in; until then, ``expire_exceptions`` is called opportunistically wherever a
user *looks* at findings (the table and the drawer — see ``app/web/views.py``),
which is enough to demo live re-surfacing without a running background process.
"""

from __future__ import annotations

from datetime import date

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.enums import ExceptionKind
from app.domain.timeutil import utcnow
from app.models import FindingException, FindingGroup
from app.models.base import now_iso
from app.services.workflow_service import transition

# The two finding_group statuses that carry an active exception. Values match
# ExceptionKind exactly (§7.4: "suppressed | accepted_risk").
EXCEPTION_STATUSES: frozenset[str] = frozenset(k.value for k in ExceptionKind)


class ExceptionError(ValueError):
    """Raised when a suppress/accept-risk request is invalid: an unknown kind,
    an empty reason, or an unparseable expiry date."""


def _validate_expiry(expires_at: str | None) -> str | None:
    if not expires_at:
        return None
    try:
        return date.fromisoformat(expires_at.strip()).isoformat()
    except ValueError as exc:
        raise ExceptionError(f"Invalid expiry date: {expires_at!r}") from exc


def create_exception(
    session: Session,
    group: FindingGroup,
    *,
    kind: str,
    reason: str,
    actor_id: int,
    expires_at: str | None = None,
) -> FindingException:
    """Suppress or accept-risk ``group``. Input is validated *before* touching
    the state machine, so a bad reason/date never leaves a half-applied
    transition. Raises :class:`ExceptionError` for bad input, or
    :class:`~app.services.workflow_service.InvalidTransition` if ``group`` isn't
    currently ``open`` — the only state §7.1 allows either exception from.
    """
    if kind not in EXCEPTION_STATUSES:
        raise ExceptionError(f"Invalid exception kind: {kind!r}")
    clean_reason = (reason or "").strip()
    if not clean_reason:
        raise ExceptionError("A reason is required")
    clean_expiry = _validate_expiry(expires_at)

    transition(session, group, kind, actor_id=actor_id, note=clean_reason)
    exc = FindingException(
        group_id=group.id,
        kind=kind,
        reason=clean_reason,
        created_by=actor_id,
        expires_at=clean_expiry,
    )
    session.add(exc)
    session.flush()
    return exc


def revoke_exception(
    session: Session,
    group: FindingGroup,
    *,
    actor_id: int | None,
    note: str = "Exception revoked",
) -> None:
    """Close ``group``'s active exception (if any) and reopen it. Used for a
    manual "Reopen" from suppressed/accepted-risk and, with a different note,
    by :func:`expire_exceptions`."""
    active = session.scalar(
        select(FindingException).where(
            FindingException.group_id == group.id, FindingException.revoked_at.is_(None)
        )
    )
    if active is not None:
        active.revoked_at = now_iso()
    transition(session, group, "open", actor_id=actor_id, note=note)


def expire_exceptions(session: Session, *, today: date | None = None) -> list[int]:
    """Revoke exceptions whose ``expires_at`` has passed and reopen their group,
    writing "Exception expired, auto-reopened" to the audit trail (§7.1's "any ->
    (auto) open | system" row). Returns the ids of groups that were reopened.

    ``expires_at`` is a plain ISO date (no time-of-day): a group is considered
    expired as soon as today's date is on or after it. Self-healing: if a group
    already left the exception state some other way (e.g. a manual reopen that
    didn't go through :func:`revoke_exception`), its stale exception row is just
    closed out here rather than double-transitioning.
    """
    cutoff = (today or utcnow().date()).isoformat()
    candidates = list(
        session.scalars(
            select(FindingException).where(
                FindingException.revoked_at.is_(None),
                FindingException.expires_at.is_not(None),
                FindingException.expires_at <= cutoff,
            )
        )
    )
    reopened: list[int] = []
    for exc in candidates:
        exc.revoked_at = now_iso()
        group = session.get(FindingGroup, exc.group_id)
        if group is not None and group.current_status in EXCEPTION_STATUSES:
            transition(session, group, "open", actor_id=None, note="Exception expired, auto-reopened")
            reopened.append(group.id)
    if candidates:
        session.flush()
    return reopened


def active_exception(session: Session, group_id: int) -> FindingException | None:
    """The currently active (unrevoked) exception for a group, or ``None``."""
    return session.scalar(
        select(FindingException).where(
            FindingException.group_id == group_id, FindingException.revoked_at.is_(None)
        )
    )


def active_exceptions(session: Session, group_ids: list[int]) -> dict[int, FindingException]:
    """Batch form of :func:`active_exception`, for the findings table."""
    if not group_ids:
        return {}
    rows = session.scalars(
        select(FindingException).where(
            FindingException.group_id.in_(group_ids), FindingException.revoked_at.is_(None)
        )
    )
    return {r.group_id: r for r in rows}
