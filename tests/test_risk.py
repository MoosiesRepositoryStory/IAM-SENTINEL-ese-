"""Risk scoring + account posture tests (§6.4, §12.1)."""

from __future__ import annotations

from app.analysis.risk import account_posture_score, posture_grade, score_finding
from app.domain.enums import Category, Severity
from app.domain.records import Finding, PrincipalRecord
from hypothesis import given
from hypothesis import strategies as st


def _finding(sev: Severity, cat: Category = Category.IDENTITY) -> Finding:
    return Finding(check_id="c", title="t", severity=sev, category=cat, recommendation="r")


def test_score_increases_with_severity() -> None:
    low = score_finding(_finding(Severity.LOW)).risk_score
    med = score_finding(_finding(Severity.MEDIUM)).risk_score
    high = score_finding(_finding(Severity.HIGH)).risk_score
    crit = score_finding(_finding(Severity.CRITICAL)).risk_score
    assert low < med < high < crit


def test_score_is_clamped_0_100() -> None:
    p = PrincipalRecord(principal_uid="x", blast_radius_score=100, role="admin")
    f = score_finding(_finding(Severity.CRITICAL, Category.PRIVILEGE), p)
    assert 0 <= f.risk_score <= 100


def test_blast_radius_modifier_raises_score() -> None:
    base = score_finding(_finding(Severity.HIGH)).risk_score
    p = PrincipalRecord(principal_uid="x", blast_radius_score=80)
    boosted = score_finding(_finding(Severity.HIGH), p).risk_score
    assert boosted >= base


def test_posture_score_clean_account_is_high() -> None:
    assert account_posture_score([]) == 100
    assert posture_grade(account_posture_score([])) == "A"


def test_posture_score_decreases_with_risk() -> None:
    clean = account_posture_score([10])
    messy = account_posture_score([90, 90, 90, 90])
    assert clean > messy


@given(scores=st.lists(st.integers(min_value=0, max_value=100), max_size=50))
def test_posture_score_bounds(scores: list[int]) -> None:
    result = account_posture_score(scores)
    assert 0 <= result <= 100


def test_grades_cover_range() -> None:
    assert posture_grade(95) == "A"
    assert posture_grade(85) == "B"
    assert posture_grade(75) == "C"
    assert posture_grade(65) == "D"
    assert posture_grade(10) == "F"
