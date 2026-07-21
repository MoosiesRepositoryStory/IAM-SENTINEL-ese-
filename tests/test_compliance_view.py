"""Compliance rollup tests (§6.5, Phase 3 Slice 4).

Builds ``finding``/``finding_group`` rows directly against a hand-made Run —
same rationale as test_diff_service: the rollup is a pure function of
persisted rows, so constructing exact before/after shapes is faster and more
precise than coaxing a real scan into a specific control state.
test_moto_ingestion covers the real-scan end-to-end path.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.compliance.mappings import framework_controls
from app.models import Account, Finding, FindingGroup, Run
from app.services.compliance_view import _natural_key, compliance_summary

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


def _finding(
    session, run: Run, *, check_id: str, severity: str = "HIGH", status: str = "open"
) -> Finding:
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
        severity=severity,
        category="identity",
        recommendation="",
        status=status,
    )
    session.add(finding)
    session.flush()
    return finding


def _cis(session, run_id: int):
    return next(fw for fw in compliance_summary(session, run_id) if fw.key == "CIS_AWS_1.4")


def _control(fw, control_id: str):
    return next(c for c in fw.controls if c.control_id == control_id)


# --- shape / completeness ----------------------------------------------------


def test_every_static_control_present_with_no_findings(db_session) -> None:
    account = _account(db_session)
    run = _run(db_session, account)
    frameworks = compliance_summary(db_session, run.id)

    static = framework_controls()
    assert {fw.key for fw in frameworks} == set(static)
    for fw in frameworks:
        assert {c.control_id for c in fw.controls} == set(static[fw.key])
        assert all(c.passing for c in fw.controls)
        assert fw.percent == 100
        assert fw.passing_controls == fw.total_controls


# --- pass/fail from status ----------------------------------------------------


def test_open_finding_fails_its_mapped_controls(db_session) -> None:
    account = _account(db_session)
    run = _run(db_session, account)
    _finding(db_session, run, check_id="iam.user.mfa_disabled", severity="HIGH")

    cis = _cis(db_session, run.id)
    assert _control(cis, "1.10").passing is False  # CIS 1.10 = mfa_disabled
    assert _control(cis, "1.10").top_severity == "HIGH"
    assert _control(cis, "1.9").passing is True  # unrelated control, unaffected
    assert cis.passing_controls == cis.total_controls - 1


@pytest.mark.parametrize("status", ["resolved", "suppressed", "accepted_risk"])
def test_non_active_statuses_do_not_fail_the_control(db_session, status) -> None:
    account = _account(db_session)
    run = _run(db_session, account)
    _finding(db_session, run, check_id="iam.user.mfa_disabled", status=status)

    cis = _cis(db_session, run.id)
    assert _control(cis, "1.10").passing is True
    assert cis.percent == 100


def test_investigating_still_counts_as_an_active_failure(db_session) -> None:
    account = _account(db_session)
    run = _run(db_session, account)
    _finding(db_session, run, check_id="iam.user.mfa_disabled", status="investigating")

    cis = _cis(db_session, run.id)
    assert _control(cis, "1.10").passing is False


# --- counts match underlying findings exactly --------------------------------


def test_finding_count_matches_exact_underlying_row_count(db_session) -> None:
    account = _account(db_session)
    run = _run(db_session, account)
    for _ in range(4):
        _finding(db_session, run, check_id="iam.user.mfa_disabled", severity="HIGH", status="open")
    _finding(
        db_session, run, check_id="iam.user.mfa_disabled", severity="HIGH", status="resolved"
    )  # excluded

    cis = _cis(db_session, run.id)
    assert _control(cis, "1.10").finding_count == 4  # not 5 — resolved doesn't count


def test_multi_check_control_sums_across_its_checks(db_session) -> None:
    """CIS 1.12 is mapped to three different check ids — a real finding under
    any of them should count, and the total should sum across all three."""
    account = _account(db_session)
    run = _run(db_session, account)
    _finding(db_session, run, check_id="iam.user.inactive", severity="MEDIUM")
    _finding(db_session, run, check_id="iam.user.inactive", severity="MEDIUM")
    _finding(db_session, run, check_id="iam.credential.unused_active", severity="MEDIUM")

    cis = _cis(db_session, run.id)
    row = _control(cis, "1.12")
    assert row.passing is False
    assert row.finding_count == 3
    assert set(row.check_ids) >= {"iam.user.inactive", "iam.credential.unused_active"}


def test_top_severity_is_the_worst_among_failing_checks_on_a_control(db_session) -> None:
    account = _account(db_session)
    run = _run(db_session, account)
    # CIS 1.16 maps to several checks; give it a MEDIUM and a CRITICAL.
    _finding(db_session, run, check_id="policy.wildcard_action", severity="MEDIUM")
    _finding(db_session, run, check_id="iam.escalation.passrole_createkey", severity="CRITICAL")

    cis = _cis(db_session, run.id)
    assert _control(cis, "1.16").top_severity == "CRITICAL"


# --- percent + ordering -------------------------------------------------------


def test_percent_is_passing_over_total_rounded(db_session) -> None:
    account = _account(db_session)
    run = _run(db_session, account)
    _finding(db_session, run, check_id="iam.user.mfa_disabled")  # fails 1.10 only

    cis = _cis(db_session, run.id)
    assert cis.total_controls == 8  # 8 distinct CIS controls in the static map
    assert cis.passing_controls == 7
    assert cis.percent == round(100 * 7 / 8)


def test_controls_sort_in_natural_not_lexicographic_order(db_session) -> None:
    account = _account(db_session)
    run = _run(db_session, account)
    cis = _cis(db_session, run.id)
    ids = [c.control_id for c in cis.controls]
    assert ids.index("1.9") < ids.index("1.10")  # lexicographic would put 1.10 first
    assert ids == sorted(ids, key=_natural_key)
