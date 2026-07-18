"""Composite risk scoring (§6.4).

Per-finding score blends the base severity weight with impact (how much damage,
driven by the affected principal's blast radius) and likelihood (how exploitable,
driven by exposure signals in the evidence). Account posture score aggregates the
open, non-excepted findings into a 0-100 "higher is better" grade.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

from app.domain.enums import Category, Severity
from app.domain.records import Finding, PrincipalRecord


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


# --------------------------------------------------------------------------
# Account posture score (§6.4) — retuned in Phase 3 Slice 5.
#
# The Phase-0 formula was `100 * exp(-sum(per_finding_risk_score) / 220)`.
# Summing forty 0-100 finding scores produces a raw risk in the thousands, and
# `exp(-thousands/220)` underflows to 0 for any non-trivial account — so the
# score sat pegged at 0 / grade F for every scanned org, carrying no signal.
# The retune keeps an exponential-decay *shape* (more risk -> lower score,
# asymptotic toward but never reaching 0) but drives it from an explicitly
# weighted, saturation-controlled risk *load* instead of a raw sum, and folds
# in the blast-radius and escalation-path data that only became real in
# Slices 1-2. Every constant below is anchored, not hand-fitted to make one
# org "look right":
#
# 1. SEVERITY_LOAD — per-finding weight by severity. Super-linear (roughly
#    doubling per tier) because a CRITICAL is categorically worse than "a few
#    HIGHs": it's direct compromise, not accumulated hygiene debt.
SEVERITY_LOAD: dict[str, float] = {"LOW": 1.0, "MEDIUM": 3.0, "HIGH": 8.0, "CRITICAL": 18.0}
#
# 2. Diminishing marginal load — the N-th finding of a given severity counts
#    less than the first. `_diminishing(n)` rises from 1 (n=1) toward an
#    asymptote of 1/DAMP (~6.7) as n grows: once an account already has a
#    dozen HIGHs it is *systemically* bad and the thirteenth barely moves the
#    needle. This is what stops a large-but-not-worse account from underflowing
#    the score to 0, while still letting the first few criticals bite hard.
_DAMP = 0.15
#
# 3. BLAST_LOAD — the single highest-blast-radius principal in the account adds
#    up to this many points as its blast radius approaches 100. A lone identity
#    that can reach everything is an account-level risk even if few findings
#    fired directly on it (§6.2 feeding §6.4).
BLAST_LOAD = 40.0
#
# 4. ESCALATION_LOAD — each finding carrying a confirmed permission-graph
#    escalation path to an admin-equivalent node (Slice 1's `graph_path`
#    evidence) adds this much, diminishing like severities. Privilege
#    escalation to admin is the single most damaging class, so it earns a
#    dedicated term *beyond* its CRITICAL severity weight.
ESCALATION_LOAD = 25.0
#
# K anchors the whole curve to one named reference account: K is the risk load
# of a "clearly failing" org — roughly four unmitigated criticals plus one
# confirmed escalation path (18*_diminishing(4) + 25 ~= 80) — so that such an
# account scores exactly 100*e^-1 ~= 37, squarely mid-F. Everything else is
# measured relative to that anchor; the demo org, being worse, lands lower
# (~14) as an *outcome*, not a fitted target.
POSTURE_K = 80.0


@dataclass(frozen=True)
class PostureFactor:
    """One finding's contribution to the account posture, reduced to just what
    the score needs. Both the analysis engine (dataclass findings) and the web
    dashboard (ORM rows) build these, so the scorer never couples to either."""

    severity: str
    blast_radius: int = 0  # affected principal's blast-radius score (0-100)
    is_escalation: bool = False  # finding carries a confirmed graph_path to admin


def _diminishing(n: int) -> float:
    """Effective count of ``n`` same-severity findings: 1 for the first, rising
    toward an asymptote of ``1/_DAMP`` (~6.7). ``_diminishing(1)==1``,
    ``_diminishing(5)~=2.9``, ``_diminishing(20)~=5.7``."""
    if n <= 0:
        return 0.0
    return n / (1 + _DAMP * (n - 1))


def account_posture_score(factors: list[PostureFactor]) -> int:
    """0-100 account posture score (higher = better) from the open, non-excepted
    findings' :class:`PostureFactor` contributions (§6.4). Empty -> 100."""
    if not factors:
        return 100

    by_sev: Counter[str] = Counter(f.severity for f in factors)
    load = sum(SEVERITY_LOAD.get(sev, 0.0) * _diminishing(n) for sev, n in by_sev.items())

    n_escalations = sum(1 for f in factors if f.is_escalation)
    load += ESCALATION_LOAD * _diminishing(n_escalations)

    max_blast = max((f.blast_radius for f in factors), default=0)
    load += BLAST_LOAD * (min(max_blast, 100) / 100)

    return _clamp(100 * math.exp(-load / POSTURE_K))


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
