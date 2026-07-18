"""Risk scoring + account posture tests (§6.4, §12.1).

Posture-score tests pin the retuned formula (Phase 3 Slice 5) against known
fixture inputs — both the exact numbers at named anchor points and the shape
properties (monotonic, bounded, non-degenerate) that motivated the retune.
"""

from __future__ import annotations

from app.analysis.risk import (
    PostureFactor,
    _diminishing,
    account_posture_score,
    posture_grade,
    score_finding,
)
from app.domain.enums import Category, Severity
from app.domain.records import Finding, PrincipalRecord
from hypothesis import given
from hypothesis import strategies as st


def _finding(sev: Severity, cat: Category = Category.IDENTITY) -> Finding:
    return Finding(check_id="c", title="t", severity=sev, category=cat, recommendation="r")


def _f(sev: str, blast: int = 0, escalation: bool = False) -> PostureFactor:
    return PostureFactor(severity=sev, blast_radius=blast, is_escalation=escalation)


# --- per-finding score (unchanged by the retune) ----------------------------


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


# --- posture: shape properties ----------------------------------------------


def test_clean_account_is_a_hundred() -> None:
    assert account_posture_score([]) == 100
    assert posture_grade(account_posture_score([])) == "A"


def test_posture_decreases_as_findings_worsen() -> None:
    one_low = account_posture_score([_f("LOW")])
    one_crit = account_posture_score([_f("CRITICAL")])
    crit_plus_blast = account_posture_score([_f("CRITICAL", blast=90)])
    assert one_low > one_crit > crit_plus_blast


def test_escalation_path_lowers_posture_beyond_severity_alone() -> None:
    plain_crit = account_posture_score([_f("CRITICAL", blast=50)])
    escalating_crit = account_posture_score([_f("CRITICAL", blast=50, escalation=True)])
    assert escalating_crit < plain_crit


@given(
    factors=st.lists(
        st.builds(
            PostureFactor,
            severity=st.sampled_from(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
            blast_radius=st.integers(min_value=0, max_value=100),
            is_escalation=st.booleans(),
        ),
        max_size=200,
    )
)
def test_posture_is_always_bounded_0_100(factors: list[PostureFactor]) -> None:
    assert 0 <= account_posture_score(factors) <= 100


def test_large_bad_account_is_non_degenerate_not_pegged_at_zero() -> None:
    """The whole point of the retune: forty HIGH findings must NOT underflow to
    0 — diminishing marginal load keeps a large-but-uniform account readable."""
    forty_highs = account_posture_score([_f("HIGH")] * 40)
    assert forty_highs > 0
    # ...and a genuinely catastrophic account still scores *lower*, so the bad
    # end of the range stays differentiated rather than all collapsing to 0.
    catastrophic = account_posture_score([_f("CRITICAL", blast=95, escalation=True)] * 40)
    assert 0 < catastrophic < forty_highs


def test_diminishing_returns_curve() -> None:
    assert _diminishing(0) == 0.0
    assert _diminishing(1) == 1.0
    assert _diminishing(2) < 2.0  # second finding worth less than the first
    # Monotonic increasing but sub-linear, asymptotic toward 1/DAMP.
    assert _diminishing(5) < _diminishing(20) < (1 / 0.15) + 0.01


# --- posture: pinned numbers at named anchors -------------------------------


def test_single_critical_is_a_B() -> None:
    # 18 load -> 100*exp(-18/80) = 80.
    assert account_posture_score([_f("CRITICAL")]) == 80


def test_reference_failing_account_lands_mid_F() -> None:
    """The K anchor: ~4 criticals + 1 escalation ≈ 80 load ≈ 37 (mid-F)."""
    ref = account_posture_score(
        [_f("CRITICAL"), _f("CRITICAL"), _f("CRITICAL"), _f("CRITICAL", escalation=True)]
    )
    assert 34 <= ref <= 40
    assert posture_grade(ref) == "F"


def test_slightly_bad_account_is_readable_B_not_F() -> None:
    score = account_posture_score([_f("HIGH"), _f("HIGH"), _f("MEDIUM")])
    assert score == 81
    assert posture_grade(score) == "B"


# --- grade bands ------------------------------------------------------------


def test_grades_cover_range() -> None:
    assert posture_grade(95) == "A"
    assert posture_grade(85) == "B"
    assert posture_grade(75) == "C"
    assert posture_grade(65) == "D"
    assert posture_grade(10) == "F"
