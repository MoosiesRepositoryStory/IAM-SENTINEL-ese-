"""The analysis engine: run all checks, score, and summarize (§3.2 step 3).

Pure and side-effect free — it takes a :class:`NormalizedDataset` and returns an
:class:`AnalysisResult`. Persistence is the caller's job (the service layer), so
the engine stays trivially testable.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from app.analysis import risk
from app.analysis.registry import REGISTRY, ActivityIndex, CheckContext
from app.compliance.mappings import compliance_tags_for, frameworks_for
from app.domain.records import Finding, NormalizedDataset, Thresholds


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    composite_score: int = 100
    counts_by_severity: dict[str, int] = field(default_factory=dict)
    counts_by_category: dict[str, int] = field(default_factory=dict)
    compliance_summary: dict[str, dict[str, int]] = field(default_factory=dict)


def build_activity_index(dataset: NormalizedDataset) -> ActivityIndex:
    """Map each principal -> set of actions actually observed in the logs.

    An event's ``event_name`` (e.g. ``AssumeRole``) is normalized to a coarse
    action label; the log window is the span between earliest and latest event.
    """
    used: dict[str, set[str]] = {}
    timestamps = []
    for ev in dataset.log_events:
        if ev.ts is not None:
            timestamps.append(ev.ts)
        if not ev.principal_uid or not ev.event_name:
            continue
        if ev.outcome == "denied":  # denied actions were not actually exercised
            continue
        used.setdefault(ev.principal_uid, set()).add(ev.event_name)
    window_days = 0
    if len(timestamps) >= 2:
        window_days = max((max(timestamps) - min(timestamps)).days, 1)
    return ActivityIndex(used_actions=used, window_days=window_days)


def run_analysis(dataset: NormalizedDataset, thresholds: Thresholds) -> AnalysisResult:
    """Execute every registered check, score findings, and aggregate summaries."""
    activity = build_activity_index(dataset)
    ctx = CheckContext(dataset=dataset, thresholds=thresholds, activity=activity)
    principals = dataset.principal_by_uid()

    findings: list[Finding] = []
    for check in REGISTRY.values():
        for finding in check.run(ctx):
            if not finding.compliance_tags:
                finding.compliance_tags = compliance_tags_for(finding.check_id)
            principal = principals.get(finding.principal_uid or "")
            risk.score_finding(finding, principal)
            findings.append(finding)

    findings.sort(key=lambda f: f.risk_score, reverse=True)

    counts_by_severity = Counter(f.severity.value for f in findings)
    counts_by_category = Counter(f.category.value for f in findings)
    compliance_summary = _summarize_compliance(findings)
    composite = risk.account_posture_score([f.risk_score for f in findings])

    return AnalysisResult(
        findings=findings,
        composite_score=composite,
        counts_by_severity=dict(counts_by_severity),
        counts_by_category=dict(counts_by_category),
        compliance_summary=compliance_summary,
    )


def _summarize_compliance(findings: list[Finding]) -> dict[str, dict[str, int]]:
    """Per-framework fail counts (a finding present == that control failing)."""
    summary: dict[str, dict[str, int]] = {}
    for finding in findings:
        for framework in frameworks_for(finding.check_id):
            bucket = summary.setdefault(framework, {"fail": 0})
            bucket["fail"] += 1
    return summary
