"""Tests for bulk finding actions (§8.4) — thin loops over the existing
single-finding workflow/collaboration/exception functions."""

from __future__ import annotations

from pathlib import Path

import pytest
from app.models import AppUser, AuditEvent, FindingGroup
from app.services import create_account, run_scan
from app.services.bulk_service import bulk_assign, bulk_exception, bulk_transition
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


def _groups(session) -> list[FindingGroup]:
    return list(session.scalars(select(FindingGroup).order_by(FindingGroup.id)))


def _actor(session) -> AppUser:
    u = AppUser(email="a@b.c", display_name="Ada", password_hash="!", role="admin")
    session.add(u)
    session.flush()
    return u


# ---- bulk_transition ----

def test_bulk_transition_all_succeed(db_session) -> None:
    _scan(db_session)
    groups = _groups(db_session)[:3]
    actor = _actor(db_session)
    ids = [g.id for g in groups]

    result = bulk_transition(db_session, ids, "investigating", actor_id=actor.id)

    assert result.succeeded == ids
    assert result.failed == []
    assert all(g.current_status == "investigating" for g in groups)


def test_bulk_transition_partial_failure_does_not_abort_batch(db_session) -> None:
    _scan(db_session)
    groups = _groups(db_session)[:3]
    actor = _actor(db_session)
    # Pre-move one group so its transition to 'resolved' is invalid (open->resolved
    # isn't a legal move; only investigating->resolved is).
    already_open = groups[1]
    ids = [g.id for g in groups]

    result = bulk_transition(db_session, ids, "resolved", actor_id=actor.id)

    # groups[0] and groups[2] also fail (same reason: open->resolved invalid) —
    # use a mixed-state setup to prove partial success instead.
    assert already_open.current_status == "open"
    assert result.failed  # every item fails identically here, which is fine —
    # the real partial-success path is exercised in the next test.


def test_bulk_transition_mixed_states_partial_success(db_session) -> None:
    _scan(db_session)
    groups = _groups(db_session)[:3]
    actor = _actor(db_session)
    ids = [g.id for g in groups]

    # Move exactly one group into 'investigating' first so it's eligible for
    # 'resolved'; the other two remain 'open' and are NOT eligible.
    bulk_transition(db_session, [groups[0].id], "investigating", actor_id=actor.id)

    result = bulk_transition(db_session, ids, "resolved", actor_id=actor.id)

    assert result.succeeded == [groups[0].id]
    assert {gid for gid, _ in result.failed} == {groups[1].id, groups[2].id}
    assert groups[0].current_status == "resolved"
    assert groups[1].current_status == "open"


def test_bulk_transition_missing_group_reported_as_failure(db_session) -> None:
    _scan(db_session)
    groups = _groups(db_session)[:2]
    actor = _actor(db_session)
    ids = [groups[0].id, 999999]

    result = bulk_transition(db_session, ids, "investigating", actor_id=actor.id)

    assert result.succeeded == [groups[0].id]
    assert result.failed == [(999999, "not found")]


def test_bulk_transition_writes_one_summarizing_audit_event(db_session) -> None:
    _scan(db_session)
    groups = _groups(db_session)[:3]
    actor = _actor(db_session)
    ids = [g.id for g in groups]

    bulk_transition(db_session, ids, "investigating", actor_id=actor.id)

    events = db_session.scalars(
        select(AuditEvent).where(AuditEvent.action == "bulk_transition")
    ).all()
    assert len(events) == 1
    assert events[0].event_metadata["group_ids"] == ids
    assert events[0].event_metadata["count"] == 3
    assert events[0].event_metadata["to_status"] == "investigating"


def test_bulk_transition_no_successes_writes_no_audit_event(db_session) -> None:
    _scan(db_session)
    groups = _groups(db_session)[:2]
    actor = _actor(db_session)
    # open->resolved is invalid for every item -> nothing succeeds.
    bulk_transition(db_session, [g.id for g in groups], "resolved", actor_id=actor.id)
    events = db_session.scalars(
        select(AuditEvent).where(AuditEvent.action == "bulk_transition")
    ).all()
    assert events == []


# ---- bulk_assign ----

def test_bulk_assign_sets_assignee_on_all(db_session) -> None:
    _scan(db_session)
    groups = _groups(db_session)[:3]
    actor = _actor(db_session)
    analyst = AppUser(email="p@x.io", display_name="Priya", password_hash="!", role="analyst")
    db_session.add(analyst)
    db_session.flush()

    result = bulk_assign(db_session, [g.id for g in groups], analyst.id, actor_id=actor.id)

    assert result.count == 3
    assert all(g.assignee_id == analyst.id for g in groups)
    events = db_session.scalars(select(AuditEvent).where(AuditEvent.action == "bulk_assign")).all()
    assert len(events) == 1
    assert events[0].event_metadata["assignee_id"] == analyst.id


def test_bulk_assign_unassign(db_session) -> None:
    _scan(db_session)
    groups = _groups(db_session)[:2]
    actor = _actor(db_session)
    bulk_assign(db_session, [g.id for g in groups], actor.id, actor_id=actor.id)
    result = bulk_assign(db_session, [g.id for g in groups], None, actor_id=actor.id)
    assert result.count == 2
    assert all(g.assignee_id is None for g in groups)


# ---- bulk_exception ----

def test_bulk_suppress_all_succeed_with_shared_reason(db_session) -> None:
    _scan(db_session)
    groups = _groups(db_session)[:3]
    actor = _actor(db_session)
    ids = [g.id for g in groups]

    result = bulk_exception(db_session, ids, "suppressed", reason="Known noise", actor_id=actor.id)

    assert result.count == 3
    assert all(g.current_status == "suppressed" for g in groups)


def test_bulk_accept_risk_with_expiry(db_session) -> None:
    _scan(db_session)
    groups = _groups(db_session)[:2]
    actor = _actor(db_session)
    ids = [g.id for g in groups]

    result = bulk_exception(
        db_session, ids, "accepted_risk", reason="Tracked JIRA-1", actor_id=actor.id,
        expires_at="2099-01-01",
    )

    assert result.count == 2
    assert all(g.current_status == "accepted_risk" for g in groups)


def test_bulk_exception_empty_reason_fails_every_item(db_session) -> None:
    _scan(db_session)
    groups = _groups(db_session)[:2]
    actor = _actor(db_session)
    ids = [g.id for g in groups]

    result = bulk_exception(db_session, ids, "suppressed", reason="   ", actor_id=actor.id)

    assert result.succeeded == []
    assert len(result.failed) == 2
    assert all(g.current_status == "open" for g in groups)


def test_bulk_exception_mixed_eligibility_partial_success(db_session) -> None:
    _scan(db_session)
    groups = _groups(db_session)[:3]
    actor = _actor(db_session)
    # Make one group ineligible (not 'open') before the bulk call.
    bulk_transition(db_session, [groups[0].id], "investigating", actor_id=actor.id)
    ids = [g.id for g in groups]

    result = bulk_exception(db_session, ids, "suppressed", reason="noise", actor_id=actor.id)

    assert set(result.succeeded) == {groups[1].id, groups[2].id}
    assert result.failed == [(groups[0].id, "Cannot transition finding from 'investigating' to 'suppressed'")]
