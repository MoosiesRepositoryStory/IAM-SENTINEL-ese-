"""Tests for suppression / accepted-risk exceptions and expiry-driven
re-surfacing (§7.4)."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from app.models import AppUser, FindingException, FindingGroup, FindingStatusHistory
from app.services import create_account, run_scan
from app.services.exception_service import (
    ExceptionError,
    active_exception,
    active_exceptions,
    create_exception,
    expire_exceptions,
    revoke_exception,
)
from app.services.finding_detail import get_finding_detail
from app.services.rbac import PermissionDenied
from app.services.workflow_service import InvalidTransition
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


# ---- create_exception ----

def test_suppress_requires_reason(db_session) -> None:
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    with pytest.raises(ExceptionError):
        create_exception(db_session, group, kind="suppressed", reason="   ", actor_id=actor.id)
    assert group.current_status == "open"  # no partial transition on bad input
    assert db_session.scalars(select(FindingException)).all() == []


def test_suppress_persists_and_transitions(db_session) -> None:
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    exc = create_exception(
        db_session, group, kind="suppressed", reason="Known noise", actor_id=actor.id
    )
    assert group.current_status == "suppressed"
    assert exc.reason == "Known noise"
    assert exc.expires_at is None
    assert exc.revoked_at is None


def test_accept_risk_with_expiry(db_session) -> None:
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    exc = create_exception(
        db_session, group, kind="accepted_risk", reason="Tracked in JIRA-42",
        actor_id=actor.id, expires_at="2099-01-01",
    )
    assert group.current_status == "accepted_risk"
    assert exc.expires_at == "2099-01-01"


def test_invalid_expiry_rejected(db_session) -> None:
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    with pytest.raises(ExceptionError):
        create_exception(
            db_session, group, kind="accepted_risk", reason="x", actor_id=actor.id,
            expires_at="not-a-date",
        )
    assert group.current_status == "open"


# ---- RBAC defense-in-depth (§10.2, Phase 4 Slice 2) ----
# The route layer (require_role) is the primary gate; these prove the
# service-layer re-check independently rejects a forged/bypassed call —
# i.e. even a caller that reached create_exception() without going through
# the decorated route still can't accept risk below admin.


def test_accept_risk_rejected_for_analyst_actor_role(db_session) -> None:
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    with pytest.raises(PermissionDenied):
        create_exception(
            db_session, group, kind="accepted_risk", reason="x",
            actor_id=actor.id, actor_role="analyst",
        )
    # Rejected before any transition — no partial state change.
    assert group.current_status == "open"
    assert db_session.scalars(select(FindingException)).all() == []


def test_accept_risk_allowed_for_admin_actor_role(db_session) -> None:
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    exc = create_exception(
        db_session, group, kind="accepted_risk", reason="Tracked in JIRA-42",
        actor_id=actor.id, actor_role="admin",
    )
    assert group.current_status == "accepted_risk"
    assert exc.reason == "Tracked in JIRA-42"


def test_accept_risk_actor_role_none_is_trusted_unchecked(db_session) -> None:
    """The default ``actor_role=None`` means "trusted internal caller, no
    check" (see rbac.py's module docstring) — every pre-existing test above
    that omits it must keep working unchanged."""
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    exc = create_exception(
        db_session, group, kind="accepted_risk", reason="x", actor_id=actor.id
    )
    assert group.current_status == "accepted_risk"
    assert exc is not None


def test_suppress_has_no_role_split_analyst_actor_role_allowed(db_session) -> None:
    """Suppression carries no admin/analyst split (§10.2) — an analyst
    ``actor_role`` must NOT be rejected the way accept-risk is."""
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    exc = create_exception(
        db_session, group, kind="suppressed", reason="Known noise",
        actor_id=actor.id, actor_role="analyst",
    )
    assert group.current_status == "suppressed"
    assert exc.reason == "Known noise"


def test_invalid_kind_rejected(db_session) -> None:
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    with pytest.raises(ExceptionError):
        create_exception(db_session, group, kind="bogus", reason="x", actor_id=actor.id)


def test_cannot_suppress_a_non_open_finding(db_session) -> None:
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    create_exception(db_session, group, kind="suppressed", reason="first", actor_id=actor.id)
    with pytest.raises(InvalidTransition):
        create_exception(db_session, group, kind="accepted_risk", reason="second", actor_id=actor.id)


def test_create_exception_writes_status_history(db_session) -> None:
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    create_exception(db_session, group, kind="suppressed", reason="noise", actor_id=actor.id)
    history = db_session.scalars(
        select(FindingStatusHistory).where(FindingStatusHistory.group_id == group.id)
    ).all()
    last = history[-1]
    assert last.from_status == "open"
    assert last.to_status == "suppressed"
    assert last.note == "noise"


# ---- revoke_exception ----

def test_revoke_closes_exception_and_reopens(db_session) -> None:
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    create_exception(db_session, group, kind="suppressed", reason="noise", actor_id=actor.id)
    revoke_exception(db_session, group, actor_id=actor.id)
    assert group.current_status == "open"
    exc = db_session.scalars(select(FindingException).where(FindingException.group_id == group.id)).first()
    assert exc.revoked_at is not None


def test_revoke_with_no_active_exception_still_reopens(db_session) -> None:
    # Defensive path: state machine says suppressed->open is valid even if the
    # exception row is somehow already gone.
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    create_exception(db_session, group, kind="suppressed", reason="noise", actor_id=actor.id)
    exc = db_session.scalars(select(FindingException)).first()
    exc.revoked_at = "already-closed"
    db_session.flush()
    revoke_exception(db_session, group, actor_id=actor.id)
    assert group.current_status == "open"


# ---- expire_exceptions ----

def test_expire_exceptions_reopens_past_expiry(db_session) -> None:
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    create_exception(
        db_session, group, kind="accepted_risk", reason="temp", actor_id=actor.id,
        expires_at="2020-01-01",
    )
    reopened = expire_exceptions(db_session, today=date(2026, 7, 14))
    assert reopened == [group.id]
    assert group.current_status == "open"
    exc = db_session.scalars(select(FindingException)).first()
    assert exc.revoked_at is not None


def test_expire_exceptions_leaves_future_expiry_alone(db_session) -> None:
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    create_exception(
        db_session, group, kind="accepted_risk", reason="temp", actor_id=actor.id,
        expires_at="2099-01-01",
    )
    reopened = expire_exceptions(db_session, today=date(2026, 7, 14))
    assert reopened == []
    assert group.current_status == "accepted_risk"


def test_expire_exceptions_ignores_no_expiry(db_session) -> None:
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    create_exception(db_session, group, kind="suppressed", reason="permanent noise", actor_id=actor.id)
    reopened = expire_exceptions(db_session, today=date(2099, 1, 1))
    assert reopened == []
    assert group.current_status == "suppressed"


def test_expire_exceptions_writes_auto_reopened_history(db_session) -> None:
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    create_exception(
        db_session, group, kind="accepted_risk", reason="temp", actor_id=actor.id,
        expires_at="2020-01-01",
    )
    expire_exceptions(db_session, today=date(2026, 7, 14))
    last = db_session.scalars(
        select(FindingStatusHistory)
        .where(FindingStatusHistory.group_id == group.id)
        .order_by(FindingStatusHistory.id.desc())
    ).first()
    assert last.to_status == "open"
    assert last.actor_id is None  # system-triggered
    assert last.note == "Exception expired, auto-reopened"


def test_expire_exceptions_is_boundary_inclusive(db_session) -> None:
    """expires_at is a date, not a timestamp: on the expiry date itself, the
    exception has already expired (no time-of-day grace period)."""
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    create_exception(
        db_session, group, kind="accepted_risk", reason="temp", actor_id=actor.id,
        expires_at="2026-07-14",
    )
    reopened = expire_exceptions(db_session, today=date(2026, 7, 14))
    assert reopened == [group.id]


def test_expire_exceptions_self_heals_stale_row(db_session) -> None:
    """If a group already left the exception state some other way, expiry just
    closes out the stale exception row rather than double-transitioning."""
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    create_exception(
        db_session, group, kind="accepted_risk", reason="temp", actor_id=actor.id,
        expires_at="2020-01-01",
    )
    exc = db_session.scalars(select(FindingException)).first()
    # Simulate a manual reopen that bypassed revoke_exception.
    from app.services.workflow_service import transition
    transition(db_session, group, "open", actor_id=actor.id, note="manual reopen")
    assert exc.revoked_at is None  # stale: still marked active

    reopened = expire_exceptions(db_session, today=date(2026, 7, 14))
    assert reopened == []  # nothing to reopen, group was already open
    assert exc.revoked_at is not None  # but the stale row got closed out


# ---- lookups ----

def test_active_exception_and_batch_lookup(db_session) -> None:
    _scan(db_session)
    groups = _groups(db_session)
    actor = _actor(db_session)
    create_exception(db_session, groups[0], kind="suppressed", reason="a", actor_id=actor.id)
    create_exception(db_session, groups[1], kind="accepted_risk", reason="b", actor_id=actor.id)

    assert active_exception(db_session, groups[0].id).reason == "a"
    assert active_exception(db_session, groups[2].id) is None

    batch = active_exceptions(db_session, [g.id for g in groups[:3]])
    assert set(batch.keys()) == {groups[0].id, groups[1].id}


def test_active_exception_none_after_revoke(db_session) -> None:
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    create_exception(db_session, group, kind="suppressed", reason="a", actor_id=actor.id)
    revoke_exception(db_session, group, actor_id=actor.id)
    assert active_exception(db_session, group.id) is None


# ---- drawer assembly ----

def test_finding_detail_exposes_exception_info(db_session) -> None:
    _scan(db_session)
    group = _groups(db_session)[0]
    actor = _actor(db_session)
    create_exception(
        db_session, group, kind="accepted_risk", reason="Tracked in JIRA-42",
        actor_id=actor.id, expires_at="2099-01-01",
    )
    detail = get_finding_detail(db_session, group.id)
    assert detail is not None
    assert detail.exception is not None
    assert detail.exception.reason == "Tracked in JIRA-42"
    assert detail.exception.expires_at == "2099-01-01"
    assert detail.exception.created_by_name == "Ada"
    assert detail.actions == [("open", "Reopen")]


def test_finding_detail_exception_is_none_when_not_active(db_session) -> None:
    _scan(db_session)
    group = _groups(db_session)[0]
    detail = get_finding_detail(db_session, group.id)
    assert detail is not None
    assert detail.exception is None
