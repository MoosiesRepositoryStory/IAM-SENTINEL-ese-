"""Tests for the status state machine + audit trail (§7.1) and drawer assembly."""

from __future__ import annotations

from pathlib import Path

import pytest
from app.models import AppUser, Finding, FindingGroup, FindingStatusHistory
from app.services import create_account, run_scan
from app.services.finding_detail import get_finding_detail
from app.services.workflow_service import (
    ALLOWED_TRANSITIONS,
    InvalidTransition,
    available_actions,
    transition,
)
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
    return run_scan(session, account.id)


def _a_group(session) -> FindingGroup:
    return session.scalars(select(FindingGroup).order_by(FindingGroup.id)).first()


def _actor(session) -> AppUser:
    u = AppUser(email="a@b.c", display_name="Ada", password_hash="!", role="admin")
    session.add(u)
    session.flush()
    return u


# ---- pure state-machine shape ----

def test_transition_table_is_self_consistent() -> None:
    # Every UI action target is an allowed transition and vice-versa.
    for status, targets in ALLOWED_TRANSITIONS.items():
        assert {to for to, _ in available_actions(status)} == targets


def test_open_offers_investigate_suppress_and_accept_risk() -> None:
    # Slice 2c adds 'suppressed' as a reachable target from open.
    targets = {to for to, _ in available_actions("open")}
    assert targets == {"investigating", "suppressed", "accepted_risk"}


def test_suppressed_offers_only_reopen() -> None:
    assert available_actions("suppressed") == [("open", "Reopen")]


# ---- transitions against real findings ----

def test_valid_transition_persists_and_records_history(db_session) -> None:
    _scan(db_session)
    group = _a_group(db_session)
    actor = _actor(db_session)
    assert group.current_status == "open"

    hist = transition(db_session, group, "investigating", actor_id=actor.id, note="mine")
    assert group.current_status == "investigating"
    assert hist.from_status == "open"
    assert hist.to_status == "investigating"
    assert hist.actor_id == actor.id
    assert hist.note == "mine"


def test_transition_syncs_finding_snapshot(db_session) -> None:
    """The current run's Finding.status must follow the group so the table pill
    reflects the change without a re-scan."""
    run = _scan(db_session)
    group = _a_group(db_session)
    transition(db_session, group, "investigating")
    snap = db_session.scalars(
        select(Finding).where(Finding.group_id == group.id, Finding.run_id == run.id)
    ).all()
    assert snap and all(f.status == "investigating" for f in snap)


def test_invalid_transition_raises_and_leaves_state(db_session) -> None:
    _scan(db_session)
    group = _a_group(db_session)
    with pytest.raises(InvalidTransition):
        transition(db_session, group, "resolved")  # open -> resolved not allowed
    assert group.current_status == "open"


def test_same_status_is_invalid(db_session) -> None:
    _scan(db_session)
    group = _a_group(db_session)
    with pytest.raises(InvalidTransition):
        transition(db_session, group, "open")


def test_full_lifecycle_open_investigate_resolve_reopen(db_session) -> None:
    _scan(db_session)
    group = _a_group(db_session)
    transition(db_session, group, "investigating")
    transition(db_session, group, "resolved")
    assert group.current_status == "resolved"
    transition(db_session, group, "open")  # reopen
    assert group.current_status == "open"

    history = db_session.scalars(
        select(FindingStatusHistory)
        .where(FindingStatusHistory.group_id == group.id)
        .order_by(FindingStatusHistory.id)
    ).all()
    # Detected(open) + 3 manual transitions.
    trail = [(h.from_status, h.to_status) for h in history]
    assert trail == [
        (None, "open"),
        ("open", "investigating"),
        ("investigating", "resolved"),
        ("resolved", "open"),
    ]


def test_accept_risk_path(db_session) -> None:
    _scan(db_session)
    group = _a_group(db_session)
    transition(db_session, group, "accepted_risk", note="known, tracked in JIRA-12")
    assert group.current_status == "accepted_risk"
    assert available_actions("accepted_risk") == [("open", "Reopen")]


# ---- drawer assembly ----

def test_get_finding_detail_shapes_payload(db_session) -> None:
    _scan(db_session)
    group = _a_group(db_session)
    actor = _actor(db_session)
    transition(db_session, group, "investigating", actor_id=actor.id, note="taking a look")

    detail = get_finding_detail(db_session, group.id)
    assert detail is not None
    assert detail.finding.group_id == group.id
    assert detail.group.current_status == "investigating"
    # Audit trail: Detected + the manual change, newest resolvable by actor name.
    assert len(detail.history) == 2
    assert detail.history[0].from_status is None  # Detected first
    assert detail.history[-1].actor_name == "Ada"
    assert detail.history[-1].note == "taking a look"
    assert detail.actions == [("resolved", "Resolve"), ("open", "Reopen")]


def test_get_finding_detail_missing_group(db_session) -> None:
    assert get_finding_detail(db_session, 424242) is None
