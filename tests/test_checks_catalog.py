"""Checks catalog tests (§8.11 /checks, Phase 3 Slice 4)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.analysis.registry import REGISTRY
from app.compliance.mappings import compliance_tags_for
from app.models import Account, Finding, FindingGroup, Run
from app.services.checks_catalog import list_checks

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


def _finding(session, run: Run, *, check_id: str, status: str = "open") -> Finding:
    group = FindingGroup(
        account_id=run.account_id, fingerprint=f"{check_id}:{status}:{uuid4()}", check_id=check_id
    )
    session.add(group)
    session.flush()
    finding = Finding(
        run_id=run.id,
        group_id=group.id,
        check_id=check_id,
        title="t",
        severity="HIGH",
        category="identity",
        recommendation="",
        status=status,
    )
    session.add(finding)
    session.flush()
    return finding


def test_no_session_lists_every_registered_check_with_zero_counts() -> None:
    rows = list_checks()
    assert len(rows) == len(REGISTRY)
    assert [r.check_id for r in rows] == sorted(r.check_id for r in rows)
    assert all(r.finding_count == 0 for r in rows)


def test_rows_carry_meta_and_compliance_tags() -> None:
    rows = {r.check_id: r for r in list_checks()}
    row = rows["iam.user.mfa_disabled"]
    assert row.severity == "HIGH"
    assert row.category == "identity"
    assert row.compliance_tags == compliance_tags_for("iam.user.mfa_disabled")
    assert row.compliance_tags  # non-empty for this check


def test_a_check_with_no_compliance_mapping_shows_empty_tags() -> None:
    # picked from _MAP's own gaps rather than hardcoding a check id that
    # might one day gain a mapping and silently stop testing anything.
    from app.compliance.mappings import _MAP  # noqa: PLC0415

    unmapped = [cid for cid in REGISTRY if cid not in _MAP]
    if not unmapped:
        pytest.skip("every check currently has a compliance mapping")
    rows = {r.check_id: r for r in list_checks()}
    assert rows[unmapped[0]].compliance_tags == []


def test_run_scoped_counts_match_exact_active_finding_rows(db_session) -> None:
    account = _account(db_session)
    run = _run(db_session, account)
    for _ in range(3):
        _finding(db_session, run, check_id="iam.user.mfa_disabled", status="open")
    _finding(db_session, run, check_id="iam.user.mfa_disabled", status="suppressed")  # excluded
    _finding(db_session, run, check_id="iam.credential.old_access_key", status="investigating")

    rows = {r.check_id: r for r in list_checks(db_session, run.id)}
    assert rows["iam.user.mfa_disabled"].finding_count == 3
    assert rows["iam.credential.old_access_key"].finding_count == 1
    assert rows["iam.user.inactive"].finding_count == 0
