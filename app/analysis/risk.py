"""Composite risk scoring (§6.4).

Per-finding score blends the base severity weight with impact (how much damage,
driven by the affected principal's blast radius) and likelihood (how exploitable,
driven by exposure signals in the evidence). Account posture score aggregates the
open, non-excepted findings into a 0-100 "higher is better" grade.
"""

from __future__ import annotations

import math

from app.domain.enums import Category, Severity
from app.domain.records import Finding, PrincipalRecord

# Tuning constant for the account posture curve. Chosen so a clean account scores
# ~95-100 and a badly misconfigured one lands ~20-40 (§6.4).
POSTURE_K = 220.0


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> int:
    return int(round(max(low, min(high, value))))


def _impact(finding: Finding, principal: PrincipalRecord | None) -> int:
    """1-5 impact sub-score from blast radius + finding category/severity."""
    score = 3
    if principal is not None:
        if principal.blast_radius_score >= 75:
            score = 5
        elif principal.blast_radius_score >= 50:
            score = 4
    if finding.category == Category.PRIVILEGE:
        score = max(score, 4)
    if finding.severity == Severity.CRITICAL:
        score = 5
    return max(1, min(5, score))


def _likelihood(finding: Finding, principal: PrincipalRecord | None) -> int:
    """1-5 likelihood sub-score from exposure signals in the evidence."""
    score = 3
    # Active brute-force / high failure counts raise exploitability.
    failures = finding.evidence.get("failure_count")
    if isinstance(failures, int) and failures >= 10:
        score += 1
    if principal is not None:
        if principal.active and principal.console_access and not principal.mfa_enabled:
            score += 1
        if not principal.active:
            score -= 1
    return max(1, min(5, score))


def score_finding(finding: Finding, principal: PrincipalRecord | None = None) -> Finding:
    """Populate ``risk_score`` / ``likelihood`` / ``impact`` on ``finding`` in place."""
    impact = _impact(finding, principal)
    likelihood = _likelihood(finding, principal)
    base = finding.severity.base_weight

    raw = 0.55 * base + 0.25 * (impact / 5 * 100) + 0.20 * (likelihood / 5 * 100)

    # Modifiers (§6.4).
    if principal is not None and principal.blast_radius_score >= 75:
        raw += 8
    if principal is not None and _is_privileged(principal, finding):
        raw += 5

    finding.impact = impact
    finding.likelihood = likelihood
    finding.risk_score = _clamp(raw)
    return finding


def _is_privileged(principal: PrincipalRecord, finding: Finding) -> bool:
    return finding.category == Category.PRIVILEGE or (principal.role or "").lower() in {
        "admin",
        "administrator",
        "root",
    }


def account_posture_score(open_risk_scores: list[int]) -> int:
    """0-100 account posture score (higher = better) from open finding risks."""
    raw_risk = sum(open_risk_scores)
    return _clamp(100 * math.exp(-raw_risk / POSTURE_K))


def posture_grade(score: int) -> str:
    """Letter grade A-F for a posture score."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"
