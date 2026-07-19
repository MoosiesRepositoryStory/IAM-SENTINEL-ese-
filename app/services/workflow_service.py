"""Finding-status state machine + audit trail (§7.1).

Status is durable on ``finding_group`` and mirrored onto the current run's
``finding`` snapshot so the table reflects a change without a re-scan. Every
transition writes one ``finding_status_history`` row (from, to, actor, note,
timestamp) — that history *is* the audit trail rendered in the drawer's Activity
tab.

The exception side-effects that ``suppressed`` and ``accepted_risk`` carry in
§7.4 — a ``finding_exception`` row with a reason + expiry + scheduler-driven
re-surfacing — live in ``app.services.exception_service``, which calls
``transition`` here so creating, revoking, or auto-expiring an exception all
still land as ordinary history rows. ``transition`` itself stays ungated
(§10.2's WORKFLOW_TRANSITION capability is analyst+ uniformly, including
exception-revoke reopens, so the route decorator alone is sufficient there);
:func:`available_actions` is the one role-aware piece in this module, since
which transitions to *offer* differs by role (§10.2's admin-only accept-risk
carve-out).
"""

from __future__ import annotations

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.models import Finding, FindingGroup, FindingStatusHistory
from app.services import rbac

# UI-facing transitions available from each state, in button order:
# (target status, verb label). ALLOWED_TRANSITIONS is derived from this so the
# state machine and the drawer footer can never drift apart.
TRANSITION_ACTIONS: dict[str, list[tuple[str, str]]] = {
    "open": [
        ("investigating", "Start investigating"),
        ("suppressed", "Suppress"),
        ("accepted_risk", "Accept risk"),
    ],
    "investigating": [("resolved", "Resolve"), ("open", "Reopen")],
    "resolved": [("open", "Reopen")],
    "accepted_risk": [("open", "Reopen")],
    "suppressed": [("open", "Reopen")],
}

ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    frm: {to for to, _ in actions} for frm, actions in TRANSITION_ACTIONS.items()
}

STATUS_LABELS: dict[str, str] = {
    "open": "Open",
    "investigating": "Investigating",
    "resolved": "Resolved",
    "accepted_risk": "Accepted risk",
    "suppressed": "Suppressed",
}


class InvalidTransition(ValueError):
    """Raised when a status change isn't permitted by the state machine."""

    def __init__(self, from_status: str, to_status: str) -> None:
        self.from_status = from_status
        self.to_status = to_status
        super().__init__(f"Cannot transition finding from '{from_status}' to '{to_status}'")


def available_actions(status: str, role: str | None = None) -> list[tuple[str, str]]:
    """Transition buttons to offer for a group currently in ``status``,
    filtered by ``role`` (§10.2): a read_only role gets none (view-only); an
    analyst gets everything except *creating* an accepted-risk exception
    (admin-only) — reopening FROM accepted_risk is still offered to analyst,
    since that's a de-escalation, not a new risk-acceptance decision, and its
    target status is "open", not "accepted_risk", so the filter below leaves
    it untouched. ``role=None`` (the default) returns every transition
    unfiltered, for callers that don't care about role (see
    ``app.services.rbac``'s module docstring on this convention)."""
    actions = TRANSITION_ACTIONS.get(status, [])
    if role is None:
        return actions
    if not rbac.at_least(role, "analyst"):
        return []
    if not rbac.at_least(role, "admin"):
        actions = [(to, label) for to, label in actions if to != "accepted_risk"]
    return actions


def transition(
    session: Session,
    group: FindingGroup,
    to_status: str,
    *,
    actor_id: int | None = None,
    note: str | None = None,
) -> FindingStatusHistory:
    """Move ``group`` to ``to_status``, recording the audit-trail entry.

    Raises :class:`InvalidTransition` if the move isn't allowed from the current
    status (a same-status no-op counts as invalid — there's nothing to record).
    Returns the created history row.
    """
    from_status = group.current_status
    if to_status not in ALLOWED_TRANSITIONS.get(from_status, set()):
        raise InvalidTransition(from_status, to_status)

    clean_note = (note or "").strip() or None
    history = FindingStatusHistory(
        group_id=group.id,
        from_status=from_status,
        to_status=to_status,
        actor_id=actor_id,
        note=clean_note,
    )
    session.add(history)
    group.current_status = to_status

    # Keep the current run's snapshot in sync so the findings table pill updates
    # without waiting for the next scan.
    if group.last_seen_run is not None:
        session.execute(
            update(Finding)
            .where(Finding.group_id == group.id, Finding.run_id == group.last_seen_run)
            .values(status=to_status)
        )
    session.flush()
    return history
