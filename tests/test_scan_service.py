"""End-to-end scan integration tests (§12.2)."""

from __future__ import annotations

from pathlib import Path

import pytest
from app.models import Finding, FindingGroup, RunSummary
from app.services import create_account, run_scan
from sqlalchemy import select

pytestmark = pytest.mark.integration

_SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def _scan_samples(session):
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


def test_scan_completes_and_persists(db_session) -> None:
    run = _scan_samples(db_session)
    assert run.status == "completed"
    assert run.composite_score is not None
    assert run.duration_ms is not None

    findings = db_session.scalars(select(Finding).where(Finding.run_id == run.id)).all()
    assert len(findings) > 10

    summary = db_session.get(RunSummary, run.id)
    assert summary is not None
    assert summary.total_findings == len(findings)


def test_golden_escalation_finding_present(db_session) -> None:
    """The seeded intern must surface as a CRITICAL privilege-escalation finding."""
    run = _scan_samples(db_session)
    escalations = db_session.scalars(
        select(Finding).where(
            Finding.run_id == run.id,
            Finding.check_id == "iam.escalation.passrole_createkey",
        )
    ).all()
    intern = [f for f in escalations if f.principal_uid == "user/intern"]
    assert intern, "expected an escalation finding for the intern"
    assert intern[0].severity == "CRITICAL"


def test_findings_are_grouped_and_open(db_session) -> None:
    run = _scan_samples(db_session)
    groups = db_session.scalars(
        select(FindingGroup).where(FindingGroup.account_id == run.account_id)
    ).all()
    assert groups
    assert all(g.current_status == "open" for g in groups)


def test_rescan_reuses_finding_groups(db_session) -> None:
    """A second scan must correlate to the same groups (workflow continuity)."""
    run1 = _scan_samples(db_session)
    groups_after_1 = db_session.scalars(select(FindingGroup)).all()
    ids_1 = {g.id for g in groups_after_1}

    # Re-scan the same account.
    run2 = run_scan(db_session, run1.account_id)
    assert run2.id != run1.id
    groups_after_2 = db_session.scalars(select(FindingGroup)).all()
    ids_2 = {g.id for g in groups_after_2}

    # No new groups created for identical findings; all carried forward.
    assert ids_1 == ids_2
    for g in groups_after_2:
        assert g.last_seen_run == run2.id
