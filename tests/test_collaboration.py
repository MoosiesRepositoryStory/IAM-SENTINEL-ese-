"""Tests for comments (§7.3) and assignment (§7.2), plus their appearance in the
unified drawer Activity timeline (§8.8)."""

from __future__ import annotations

from pathlib import Path

import pytest
from app.models import AppUser, AuditEvent, FindingComment, FindingGroup
from app.services import create_account, run_scan
from app.services.collaboration import (
    CommentError,
    active_users,
    add_comment,
    assign,
    assignment_events,
)
from app.services.finding_detail import get_finding_detail
from sqlalchemy import select

pytestmark = pytest.mark.integration

_SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def _scan(session):
    account = create_account(
        session,
        name="Acme Corp",
        source_type="file",
        source_config={
            "inventory_path": str(_SAMPLES / "users.csv"),
            "policies_path": str(_SAMPLES / "policies.json"),
            "logs_path": str(_SAMPLES / "auth.log"),
        },
    )
    run_scan(session, account.id)


def _group(session) -> FindingGroup:
    return session.scalars(select(FindingGroup).order_by(FindingGroup.id)).first()


def _user(session, name: str, role: str = "analyst") -> AppUser:
    u = AppUser(email=f"{name}@x.io", display_name=name, password_hash="!", role=role,
                is_active=True)
    session.add(u)
    session.flush()
    return u


# ---- comments ----

def test_add_comment_persists(db_session) -> None:
    _scan(db_session)
    group = _group(db_session)
    author = _user(db_session, "Ada")
    c = add_comment(db_session, group, author_id=author.id, body="  escalation risk  ")
    assert c.id is not None
    assert c.body == "escalation risk"  # trimmed
    stored = db_session.scalars(
        select(FindingComment).where(FindingComment.group_id == group.id)
    ).all()
    assert len(stored) == 1
    assert stored[0].author_id == author.id


def test_empty_comment_rejected(db_session) -> None:
    _scan(db_session)
    group = _group(db_session)
    author = _user(db_session, "Ada")
    with pytest.raises(CommentError):
        add_comment(db_session, group, author_id=author.id, body="   ")
    assert db_session.scalars(select(FindingComment)).all() == []


# ---- assignment ----

def test_assign_sets_and_audits(db_session) -> None:
    _scan(db_session)
    group = _group(db_session)
    analyst = _user(db_session, "Priya")
    actor = _user(db_session, "Admin", role="admin")

    assign(db_session, group, assignee_id=analyst.id, actor_id=actor.id)
    assert group.assignee_id == analyst.id

    events = assignment_events(db_session, group.id)
    assert len(events) == 1
    assert events[0].action == "assign"
    assert events[0].event_metadata["to_name"] == "Priya"


def test_reassign_and_unassign(db_session) -> None:
    _scan(db_session)
    group = _group(db_session)
    p = _user(db_session, "Priya")
    s = _user(db_session, "Sam")
    actor = _user(db_session, "Admin", role="admin")

    assign(db_session, group, assignee_id=p.id, actor_id=actor.id)
    assign(db_session, group, assignee_id=s.id, actor_id=actor.id)
    assign(db_session, group, assignee_id=None, actor_id=actor.id)
    assert group.assignee_id is None

    events = assignment_events(db_session, group.id)
    assert [e.action for e in events] == ["assign", "assign", "unassign"]


def test_assign_same_user_is_noop(db_session) -> None:
    _scan(db_session)
    group = _group(db_session)
    p = _user(db_session, "Priya")
    actor = _user(db_session, "Admin", role="admin")
    assign(db_session, group, assignee_id=p.id, actor_id=actor.id)
    assign(db_session, group, assignee_id=p.id, actor_id=actor.id)  # no-op
    assert db_session.scalars(select(AuditEvent)).all().__len__() == 1


def test_active_users_excludes_inactive(db_session) -> None:
    _scan(db_session)
    _user(db_session, "Active")
    inactive = _user(db_session, "Gone")
    inactive.is_active = False
    db_session.flush()
    names = [u.display_name for u in active_users(db_session)]
    assert "Active" in names
    assert "Gone" not in names


# ---- unified activity timeline ----

def test_activity_timeline_merges_status_comment_assignment(db_session) -> None:
    _scan(db_session)
    group = _group(db_session)
    actor = _user(db_session, "Admin", role="admin")

    add_comment(db_session, group, author_id=actor.id, body="looking now")
    assign(db_session, group, assignee_id=actor.id, actor_id=actor.id)

    detail = get_finding_detail(db_session, group.id)
    assert detail is not None
    kinds = {i.kind for i in detail.activity}
    assert kinds == {"status", "comment", "assignment"}
    # 'Detected' status entry sorts first chronologically.
    assert detail.activity[0].kind == "status"
    assert detail.activity[0].from_status is None
    assert detail.assignee_name == "Admin"

    comment_item = next(i for i in detail.activity if i.kind == "comment")
    assert comment_item.body == "looking now"
    assign_item = next(i for i in detail.activity if i.kind == "assignment")
    assert assign_item.assign_to == "Admin"
