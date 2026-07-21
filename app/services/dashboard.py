"""Dashboard data assembly (§8.11 /dashboard, Phase 3 Slice 5).

The dashboard recomputes the *live* account posture from the current run's
currently-active findings (open/investigating), so suppressing or resolving a
finding lifts the gauge — as opposed to ``run.composite_score``, the snapshot
frozen at scan time that feeds the trend. Both use the identical
``risk.account_posture_score`` over ``PostureFactor``s, so at scan time (when
everything is open) they agree.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.risk import PostureFactor, account_posture_score, posture_grade
from app.models import Finding, Principal, Run

_ACTIVE_STATUSES = ("open", "investigating")


@dataclass
class RiskyPrincipal:
    principal_uid: str
    username: str
    blast_radius: int
    finding_count: int
    total_risk: int  # sum of active finding risk scores — the differentiator


@dataclass
class DashboardData:
    run: Run
    posture: int
    grade: str
    total_active: int
    severity_counts: dict[str, int] = field(default_factory=dict)
    riskiest: list[RiskyPrincipal] = field(default_factory=list)


def _posture_factors(
    active: list[Finding], principals: dict[str, Principal]
) -> list[PostureFactor]:
    factors = []
    for f in active:
        p = principals.get(f.principal_uid or "")
        factors.append(
            PostureFactor(
                severity=f.severity,
                blast_radius=(p.blast_radius_score or 0) if p is not None else 0,
                is_escalation=bool((f.evidence or {}).get("graph_path")),
            )
        )
    return factors


def build_dashboard(session: Session, run_id: int) -> DashboardData:
    run = session.get(Run, run_id)
    if run is None:  # pragma: no cover - caller guards on a completed run existing
        raise ValueError(f"Run {run_id} not found")

    active = list(
        session.scalars(
            select(Finding).where(Finding.run_id == run_id, Finding.status.in_(_ACTIVE_STATUSES))
        )
    )
    principals = {
        p.principal_uid: p
        for p in session.scalars(select(Principal).where(Principal.run_id == run_id))
    }

    posture = account_posture_score(_posture_factors(active, principals))
    severity_counts = Counter(f.severity for f in active)

    # Per-principal risk aggregate — this is where "a slightly-bad vs a
    # catastrophically-bad principal" reads at a glance (§6.4 differentiation).
    agg: dict[str, list[Finding]] = {}
    for f in active:
        if f.principal_uid:
            agg.setdefault(f.principal_uid, []).append(f)
    riskiest = [
        RiskyPrincipal(
            principal_uid=uid,
            username=(
                (principals[uid].username if uid in principals else None) or uid.rsplit("/", 1)[-1]
            ),
            blast_radius=(principals[uid].blast_radius_score or 0) if uid in principals else 0,
            finding_count=len(fs),
            total_risk=sum(f.risk_score for f in fs),
        )
        for uid, fs in agg.items()
    ]
    riskiest.sort(key=lambda r: (r.total_risk, r.blast_radius), reverse=True)

    return DashboardData(
        run=run,
        posture=posture,
        grade=posture_grade(posture),
        total_active=len(active),
        severity_counts=dict(severity_counts),
        riskiest=riskiest[:6],
    )
