"""Dashboard data-assembly tests (§8.11 / §6.4, Phase 3 Slice 5)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.models import Account, Finding, FindingGroup, Principal, Run
from app.services.dashboard import build_dashboard

pytestmark = pytest.mark.integration


def _account(session) -> Account:
    account = Account(name="Acme", provider="aws", source_type="file", source_config={})
    session.add(account)
    session.flush()
    return account


def _run(session, account: Account) -> Run:
    run = Run(account_id=account.id, status="completed", trigger="manual", thresholds={})
    session.add(run)
    session.flush()
    return run


def _principal(session, run: Run, uid: str, *, blast: int) -> None:
    session.add(
        Principal(
            run_id=run.id, principal_uid=uid, kind="user", username=uid, blast_radius_score=blast
        )
    )
    session.flush()


def _finding(
    session,
    run: Run,
    *,
    principal_uid: str,
    severity: str = "HIGH",
    risk: int = 50,
    status: str = "open",
    evidence: dict | None = None,
) -> None:
    group = FindingGroup(
        account_id=run.account_id, fingerprint=str(uuid4()), check_id="iam.user.mfa_disabled"
    )
    session.add(group)
    session.flush()
    session.add(
        Finding(
            run_id=run.id,
            group_id=group.id,
            check_id="iam.user.mfa_disabled",
            title="t",
            severity=severity,
            category="identity",
            principal_uid=principal_uid,
            risk_score=risk,
            evidence=evidence or {},
            recommendation="",
            status=status,
        )
    )
    session.flush()


def test_dashboard_posture_and_grade(db_session) -> None:
    account = _account(db_session)
    run = _run(db_session, account)
    _principal(db_session, run, "user/intern", blast=90)
    _finding(db_session, run, principal_uid="user/intern", severity="CRITICAL", risk=95)

    data = build_dashboard(db_session, run.id)
    assert data.total_active == 1
    assert data.severity_counts == {"CRITICAL": 1}
    assert 0 < data.posture < 100
    assert data.grade in {"A", "B", "C", "D", "F"}


def test_riskiest_principals_ordered_and_differentiated(db_session) -> None:
    """The 'catastrophic vs slightly-bad principal' differentiation reads here:
    intern (a crit + a high) must outrank carol (one medium)."""
    account = _account(db_session)
    run = _run(db_session, account)
    _principal(db_session, run, "user/intern", blast=90)
    _principal(db_session, run, "user/carol", blast=5)
    _finding(db_session, run, principal_uid="user/intern", severity="CRITICAL", risk=95)
    _finding(db_session, run, principal_uid="user/intern", severity="HIGH", risk=70)
    _finding(db_session, run, principal_uid="user/carol", severity="MEDIUM", risk=40)

    data = build_dashboard(db_session, run.id)
    names = [p.username for p in data.riskiest]
    assert names[0] == "user/intern"
    assert names[1] == "user/carol"
    assert data.riskiest[0].total_risk == 165  # 95 + 70
    assert data.riskiest[0].finding_count == 2
    assert data.riskiest[1].total_risk == 40


def test_suppressed_findings_lift_the_live_posture(db_session) -> None:
    """The live gauge excludes non-active findings, so suppressing one raises
    the score — the behaviour that distinguishes it from the frozen snapshot."""
    account = _account(db_session)
    run = _run(db_session, account)
    _principal(db_session, run, "user/x", blast=50)
    _finding(db_session, run, principal_uid="user/x", severity="CRITICAL", risk=90, status="open")
    before = build_dashboard(db_session, run.id).posture

    _finding(
        db_session, run, principal_uid="user/x", severity="CRITICAL", risk=90, status="suppressed"
    )
    after = build_dashboard(db_session, run.id).posture
    assert after == before  # a suppressed finding doesn't drag the score down


def test_escalation_evidence_counts_against_posture(db_session) -> None:
    account = _account(db_session)
    run = _run(db_session, account)
    _principal(db_session, run, "user/x", blast=50)
    _finding(db_session, run, principal_uid="user/x", severity="CRITICAL", risk=90)
    plain = build_dashboard(db_session, run.id).posture

    run2 = _run(db_session, account)
    _principal(db_session, run2, "user/x", blast=50)
    _finding(
        db_session,
        run2,
        principal_uid="user/x",
        severity="CRITICAL",
        risk=90,
        evidence={"graph_path": ["user/x", "user/admin"]},
    )
    escalating = build_dashboard(db_session, run2.id).posture
    assert escalating < plain
