"""Comments (§7.3) and assignment (§7.2) on a finding group.

Both are collaboration actions distinct from a status change: a comment is a
``finding_comment`` row; an assignment change updates ``finding_group.assignee_id``
and records an ``audit_event`` so it can appear in the drawer's unified Activity
timeline (§8.8). Author/actor attribution uses the seeded demo user until auth
lands in Phase 4.

Scope note (Slice 2b): plain-text comment bodies (escaped in the template). The
spec's markdown rendering + @mention chips and comment edit/delete are deferred —
add + list is what this slice delivers.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AppUser, AuditEvent, FindingComment, FindingGroup

_GROUP_TARGET = "finding_group:{}"


class CommentError(ValueError):
    """Raised when a comment can't be created (e.g. empty body)."""


def active_users(session: Session) -> list[AppUser]:
    """Active app users, for the assignee picker."""
    return list(
        session.scalars(
            select(AppUser).where(AppUser.is_active.is_(True)).order_by(AppUser.display_name)
        )
    )


def add_comment(
    session: Session, group: FindingGroup, *, author_id: int, body: str
) -> FindingComment:
    """Attach a comment to ``group``. Empty/whitespace bodies are rejected."""
    clean = (body or "").strip()
    if not clean:
        raise CommentError("Comment body cannot be empty")
    comment = FindingComment(group_id=group.id, author_id=author_id, body=clean)
    session.add(comment)
    session.flush()
    return comment


def assign(
    session: Session,
    group: FindingGroup,
    *,
    assignee_id: int | None,
    actor_id: int | None,
) -> FindingGroup:
    """Set (or clear, when ``assignee_id`` is None) the group's assignee and record
    an audit event. A no-op assignment (same assignee) is ignored silently."""
    previous = group.assignee_id
    if previous == assignee_id:
        return group

    prev_name = _display_name(session, previous)
    new_name = _display_name(session, assignee_id)
    group.assignee_id = assignee_id
    session.add(
        AuditEvent(
            actor_id=actor_id,
            action="unassign" if assignee_id is None else "assign",
            target=_GROUP_TARGET.format(group.id),
            event_metadata={
                "from_id": previous,
                "from_name": prev_name,
                "to_id": assignee_id,
                "to_name": new_name,
            },
        )
    )
    session.flush()
    return group


def assignment_events(session: Session, group_id: int) -> list[AuditEvent]:
    """Assignment audit events for a group, oldest first (for the timeline)."""
    return list(
        session.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.target == _GROUP_TARGET.format(group_id),
                AuditEvent.action.in_(("assign", "unassign")),
            )
            .order_by(AuditEvent.id)
        )
    )


def _display_name(session: Session, user_id: int | None) -> str | None:
    if user_id is None:
        return None
    return session.scalar(select(AppUser.display_name).where(AppUser.id == user_id))
