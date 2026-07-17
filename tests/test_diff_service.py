"""DiffService set-math + delta tests (§5.4).

These build ``finding``/``finding_group`` rows directly rather than running two
real scans: the diff is a pure function of persisted rows, so constructing the
exact before/after shape per case is both faster and far more precise than
trying to coax a scanner into producing one. ``test_moto_ingestion`` covers the
real two-scan drift path end to end.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.models import Account, Finding, FindingGroup, Run
from app.services.diff_service import DiffError, default_diff_pair, diff

pytestmark = pytest.mark.integration


def _account(session) -> Account:
    account = Account(name="Acme", provider="aws", source_type="file", source_config={})
    session.add(account)
    session.flush()
    return account


def _run(session, account: Account, *, score: int | None = None, status: str = "completed") -> Run:
    run = Run(account_id=account.id, status=status, trigger="manual", thresholds={})
    run.composite_score = score
    session.add(run)
    session.flush()
    return run


def _group(session, account: Account, fingerprint: str) -> FindingGroup:
    group = FindingGroup(
        account_id=account.id,
        fingerprint=fingerprint,
        check_id="iam.user.mfa_disabled",
        principal_uid="user/x",
    )
    session.add(group)
    session.flush()
    return group


def _finding(
    session,
    run: Run,
    group: FindingGroup,
    *,
    severity: str = "HIGH",
    risk: int = 50,
    status: str = "open",
    evidence: dict[str, Any] | None = None,
    title: str = "A finding",
) -> Finding:
    finding = Finding(
        run_id=run.id,
        group_id=group.id,
        check_id=group.check_id,
        title=title,
        severity=severity,
        category="identity",
        principal_uid=group.principal_uid,
        risk_score=risk,
        evidence=evidence if evidence is not None else {},
        recommendation="",
        status=status,
    )
    session.add(finding)
    session.flush()
    return finding


# -- set math ---------------------------------------------------------------


def test_new_resolved_and_unchanged_are_partitioned_by_fingerprint(db_session) -> None:
    account = _account(db_session)
    run_a, run_b = _run(db_session, account), _run(db_session, account)
    stays = _group(db_session, account, "fp-stays")
    goes = _group(db_session, account, "fp-goes")
    arrives = _group(db_session, account, "fp-arrives")

    # Identical on both sides -> unchanged (counted, not carded).
    _finding(db_session, run_a, stays, evidence={"n": 1})
    _finding(db_session, run_b, stays, evidence={"n": 1})
    _finding(db_session, run_a, goes)  # only in A -> resolved
    _finding(db_session, run_b, arrives)  # only in B -> new

    d = diff(db_session, run_a.id, run_b.id)

    assert [c.fingerprint for c in d.new] == ["fp-arrives"]
    assert [c.fingerprint for c in d.resolved] == ["fp-goes"]
    assert d.unchanged_count == 1
    assert d.changed_count == 0
    assert not d.is_empty


def test_argument_order_does_not_matter_diff_is_always_oldest_to_newest(db_session) -> None:
    """§5.4 mandates oldest->newest. Passing the pair backwards must not invert
    'new' and 'resolved' — a URL with a>b is a caller mistake, not a request to
    diff backwards in time."""
    account = _account(db_session)
    run_a, run_b = _run(db_session, account), _run(db_session, account)
    _finding(db_session, run_b, _group(db_session, account, "fp-arrives"))

    forwards = diff(db_session, run_a.id, run_b.id)
    backwards = diff(db_session, run_b.id, run_a.id)

    assert [c.fingerprint for c in forwards.new] == ["fp-arrives"]
    assert [c.fingerprint for c in backwards.new] == ["fp-arrives"]
    assert backwards.run_a.id == run_a.id and backwards.run_b.id == run_b.id


def test_identical_runs_report_empty_diff(db_session) -> None:
    account = _account(db_session)
    run_a, run_b = _run(db_session, account), _run(db_session, account)
    group = _group(db_session, account, "fp-1")
    _finding(db_session, run_a, group, evidence={"n": 1})
    _finding(db_session, run_b, group, evidence={"n": 1})

    d = diff(db_session, run_a.id, run_b.id)

    assert d.is_empty
    assert d.unchanged_count == 1
    assert d.net_risk == 0


# -- deltas -----------------------------------------------------------------


def test_risk_change_marks_finding_changed_with_signed_delta(db_session) -> None:
    account = _account(db_session)
    run_a, run_b = _run(db_session, account), _run(db_session, account)
    group = _group(db_session, account, "fp-1")
    _finding(db_session, run_a, group, risk=70)
    _finding(db_session, run_b, group, risk=52)

    d = diff(db_session, run_a.id, run_b.id)

    assert d.changed_count == 1
    delta = d.changed[0].delta
    assert delta.risk_changed and not delta.severity_changed
    assert (delta.risk_before, delta.risk_after) == (70, 52)
    assert delta.risk_delta == -18


def test_severity_and_status_changes_are_detected(db_session) -> None:
    account = _account(db_session)
    run_a, run_b = _run(db_session, account), _run(db_session, account)
    group = _group(db_session, account, "fp-1")
    _finding(db_session, run_a, group, severity="MEDIUM", status="open")
    _finding(db_session, run_b, group, severity="CRITICAL", status="investigating")

    delta = diff(db_session, run_a.id, run_b.id).changed[0].delta

    assert (delta.severity_before, delta.severity_after) == ("MEDIUM", "CRITICAL")
    assert delta.severity_changed
    assert (delta.status_before, delta.status_after) == ("open", "investigating")
    assert delta.status_changed


def test_evidence_value_change_is_reported_key_by_key(db_session) -> None:
    """§5.4's own example: a failed-login count moving 12 -> 40."""
    account = _account(db_session)
    run_a, run_b = _run(db_session, account), _run(db_session, account)
    group = _group(db_session, account, "fp-1")
    _finding(db_session, run_a, group, evidence={"failure_count": 12, "threshold": 5})
    _finding(db_session, run_b, group, evidence={"failure_count": 40, "threshold": 5})

    delta = diff(db_session, run_a.id, run_b.id).changed[0].delta

    # Only the key that actually moved is reported; `threshold` is untouched.
    assert len(delta.evidence_changes) == 1
    change = delta.evidence_changes[0]
    assert (change.key, change.before, change.after) == ("failure_count", 12, 40)


def test_evidence_key_added_or_removed_counts_as_a_change(db_session) -> None:
    """A key present on only one side must surface (as None on the other) rather
    than being skipped by a keys-in-common comparison."""
    account = _account(db_session)
    run_a, run_b = _run(db_session, account), _run(db_session, account)
    group = _group(db_session, account, "fp-1")
    _finding(db_session, run_a, group, evidence={"gone": 1})
    _finding(db_session, run_b, group, evidence={"added": 2})

    delta = diff(db_session, run_a.id, run_b.id).changed[0].delta

    assert {(c.key, c.before, c.after) for c in delta.evidence_changes} == {
        ("gone", 1, None),
        ("added", None, 2),
    }


def test_finding_identical_in_every_compared_field_is_not_changed(db_session) -> None:
    """Guards the has_changes gate: a finding whose id/title differ per run (they
    always do) must not be mistaken for drift."""
    account = _account(db_session)
    run_a, run_b = _run(db_session, account), _run(db_session, account)
    group = _group(db_session, account, "fp-1")
    _finding(db_session, run_a, group, risk=50, evidence={"n": 1}, title="run A wording")
    _finding(db_session, run_b, group, risk=50, evidence={"n": 1}, title="run B wording")

    d = diff(db_session, run_a.id, run_b.id)

    assert d.changed_count == 0
    assert d.unchanged_count == 1


# -- banner math ------------------------------------------------------------


def test_net_risk_spans_every_finding_not_just_the_cards(db_session) -> None:
    """net_risk is run B's total risk minus run A's, so it moves for re-scored
    findings too — not only for ones that appeared or vanished."""
    account = _account(db_session)
    run_a, run_b = _run(db_session, account), _run(db_session, account)
    rescored = _group(db_session, account, "fp-rescored")
    added = _group(db_session, account, "fp-added")
    removed = _group(db_session, account, "fp-removed")

    _finding(db_session, run_a, rescored, risk=40)
    _finding(db_session, run_b, rescored, risk=60)  # +20 from a change
    _finding(db_session, run_a, removed, risk=30)  # -30 resolved
    _finding(db_session, run_b, added, risk=90)  # +90 new

    d = diff(db_session, run_a.id, run_b.id)

    assert d.risk_before == 70  # 40 + 30
    assert d.risk_after == 150  # 60 + 90
    assert d.net_risk == 80


def test_score_before_after_and_delta_come_from_the_runs(db_session) -> None:
    account = _account(db_session)
    run_a = _run(db_session, account, score=74)
    run_b = _run(db_session, account, score=68)

    d = diff(db_session, run_a.id, run_b.id)

    assert (d.score_before, d.score_after, d.score_delta) == (74, 68, -6)


def test_score_delta_is_none_when_a_run_never_scored(db_session) -> None:
    account = _account(db_session)
    run_a = _run(db_session, account, score=None)
    run_b = _run(db_session, account, score=68)

    assert diff(db_session, run_a.id, run_b.id).score_delta is None


# -- guards -----------------------------------------------------------------


def test_diffing_runs_from_different_accounts_is_rejected(db_session) -> None:
    a1, a2 = _account(db_session), _account(db_session)
    run_a, run_b = _run(db_session, a1), _run(db_session, a2)

    with pytest.raises(DiffError, match="different accounts"):
        diff(db_session, run_a.id, run_b.id)


def test_diffing_a_run_against_itself_is_rejected(db_session) -> None:
    account = _account(db_session)
    run = _run(db_session, account)

    with pytest.raises(DiffError, match="itself"):
        diff(db_session, run.id, run.id)


def test_missing_run_is_rejected(db_session) -> None:
    account = _account(db_session)
    run = _run(db_session, account)

    with pytest.raises(DiffError, match="not found"):
        diff(db_session, run.id, 9999)


# -- default pair -----------------------------------------------------------


def test_default_pair_is_previous_vs_latest_completed(db_session) -> None:
    account = _account(db_session)
    _run(db_session, account)  # oldest
    middle = _run(db_session, account)
    latest = _run(db_session, account)
    _run(db_session, account, status="failed")  # must be ignored

    assert default_diff_pair(db_session, account.id) == (middle.id, latest.id)


def test_default_pair_is_none_with_fewer_than_two_completed_runs(db_session) -> None:
    account = _account(db_session)
    assert default_diff_pair(db_session, account.id) is None

    _run(db_session, account)
    _run(db_session, account, status="failed")
    assert default_diff_pair(db_session, account.id) is None
