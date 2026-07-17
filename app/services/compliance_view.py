"""Compliance framework rollup (§6.5 rendering, Phase 3 Slice 4).

Per-framework pass/fail checklists over one run's findings. The control set
itself is static (``compliance.mappings.framework_controls``); this module
only asks which of those controls currently have an active failure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis.registry import REGISTRY
from app.compliance.mappings import FRAMEWORKS, framework_controls
from app.models import Finding

# Statuses that constitute an ACTIVE failure for compliance purposes. Mirrors
# risk.py's account_posture_score philosophy: a suppressed/accepted-risk
# finding is an org-accepted exception (still stored, still visible, but not
# counted against the live posture) — the same call made here so a control an
# operator has explicitly accepted the risk on reads as passing, not as a
# standing compliance failure the page keeps nagging about.
_ACTIVE_STATUSES = ("open", "investigating")

_SEV_RANK: dict[str, int] = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

_NATSORT = re.compile(r"(\d+)")


def _natural_key(s: str) -> tuple:
    """Sort control ids in human order across mixed formats: CIS's "1.9" <
    "1.10" (numeric, not lexicographic), SOC2's "CC6.1", NIST's "AC-2(3)"."""
    return tuple(int(t) if t.isdigit() else t for t in _NATSORT.split(s))


@dataclass
class ControlRow:
    control_id: str
    check_ids: list[str] = field(default_factory=list)
    check_titles: list[str] = field(default_factory=list)
    passing: bool = True
    finding_count: int = 0
    top_severity: str | None = None


@dataclass
class FrameworkSummary:
    key: str
    label: str
    total_controls: int
    passing_controls: int
    percent: int
    controls: list[ControlRow] = field(default_factory=list)

    @property
    def failing_controls(self) -> int:
        return self.total_controls - self.passing_controls


def compliance_summary(session: Session, run_id: int) -> list[FrameworkSummary]:
    """Per-framework checklist for ``run_id``: every control from the static
    map, marked pass/fail from this run's active (open/investigating)
    findings, sorted framework-then-control in natural order."""
    rows = session.execute(
        select(Finding.check_id, Finding.severity, func.count())
        .where(Finding.run_id == run_id, Finding.status.in_(_ACTIVE_STATUSES))
        .group_by(Finding.check_id, Finding.severity)
    ).all()

    counts: dict[str, int] = {}
    top_sev: dict[str, str] = {}
    for check_id, severity, count in rows:
        counts[check_id] = counts.get(check_id, 0) + count
        if check_id not in top_sev or _SEV_RANK[severity] > _SEV_RANK[top_sev[check_id]]:
            top_sev[check_id] = severity

    summaries: list[FrameworkSummary] = []
    for key, controls_map in sorted(framework_controls().items()):
        control_rows: list[ControlRow] = []
        for control_id in sorted(controls_map, key=_natural_key):
            check_ids = controls_map[control_id]
            failing_checks = [c for c in check_ids if c in counts]
            sevs = [top_sev[c] for c in failing_checks]
            control_rows.append(
                ControlRow(
                    control_id=control_id,
                    check_ids=check_ids,
                    check_titles=[REGISTRY[c].meta.title for c in check_ids if c in REGISTRY],
                    passing=not failing_checks,
                    finding_count=sum(counts.get(c, 0) for c in check_ids),
                    top_severity=max(sevs, key=lambda s: _SEV_RANK[s]) if sevs else None,
                )
            )
        total = len(control_rows)
        passing_n = sum(1 for c in control_rows if c.passing)
        summaries.append(
            FrameworkSummary(
                key=key,
                label=FRAMEWORKS.get(key, key),
                total_controls=total,
                passing_controls=passing_n,
                percent=round(100 * passing_n / total) if total else 100,
                controls=control_rows,
            )
        )
    return summaries
