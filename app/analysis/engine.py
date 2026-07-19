"""The analysis engine: run all checks, score, and summarize (§3.2 step 3).

Pure and side-effect free — it takes a :class:`NormalizedDataset` and returns an
:class:`AnalysisResult`. Persistence is the caller's job (the service layer), so
the engine stays trivially testable.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from app.analysis import graph as graph_module
from app.analysis import risk
from app.analysis.graph import GraphEdge
from app.analysis.registry import REGISTRY, ActivityIndex, CheckContext
from app.compliance.mappings import compliance_tags_for, frameworks_for
from app.domain import logparse
from app.domain.records import Finding, NormalizedDataset, Thresholds


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    composite_score: int = 100
    counts_by_severity: dict[str, int] = field(default_factory=dict)
    counts_by_category: dict[str, int] = field(default_factory=dict)
    compliance_summary: dict[str, dict[str, int]] = field(default_factory=dict)
    graph_edges: list[GraphEdge] = field(default_factory=list)


def build_activity_index(dataset: NormalizedDataset) -> ActivityIndex:
    """Derive the per-principal activity picture the least-privilege engine and
    credential checks consume (§6.3).

    Two things come out of one pass over ``log_events``:

    - ``used_actions`` — the set of IAM ``service:Action`` strings a principal
      *successfully* exercised, normalized from CloudTrail ``(eventSource,
      eventName)`` so it lines up with granted actions. Only events with a
      confirmed ``outcome == "success"`` count; sign-in events, denied/failed
      attempts, and anything with an unknown/missing outcome are excluded — a
      least-privilege recommendation must not treat "we don't know" as "used."
    - ``event_counts`` — every observed event for a principal (successful,
      failed, or denied), the raw "did we see this identity at all / how much"
      signal behind the sufficiency gate and ``is_active``.

    The log window is the span between the earliest and latest event.
    """
    used: dict[str, set[str]] = {}
    counts: dict[str, int] = {}
    timestamps = []
    for ev in dataset.log_events:
        if ev.ts is not None:
            timestamps.append(ev.ts)
        if not ev.principal_uid:
            continue
        # Any observed event (incl. failed/denied) counts as "we saw them".
        counts[ev.principal_uid] = counts.get(ev.principal_uid, 0) + 1
        if ev.outcome != "success":  # only a confirmed success was actually exercised
            continue
        action = logparse.to_iam_action(ev.event_source, ev.event_name)
        if action is not None:  # None = a login / unqualifiable event, not an action
            used.setdefault(ev.principal_uid, set()).add(action)
    window_days = 0
    if len(timestamps) >= 2:
        window_days = max((max(timestamps) - min(timestamps)).days, 1)
    return ActivityIndex(used_actions=used, event_counts=counts, window_days=window_days)


def run_analysis(dataset: NormalizedDataset, thresholds: Thresholds) -> AnalysisResult:
    """Execute every registered check, score findings, and aggregate summaries."""
    activity = build_activity_index(dataset)
    # Builds the permission graph and writes blast_radius_score/reachable_*
    # onto each PrincipalRecord in place *before* checks run, so risk.py's
    # impact scoring (below) sees real numbers, not the Phase-0 placeholder 0.
    graph_result = graph_module.build(dataset)
    ctx = CheckContext(
        dataset=dataset, thresholds=thresholds, activity=activity, graph=graph_result
    )
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
    # At scan time every finding is newly open, so the stored composite score is
    # the posture over all of them; the dashboard recomputes the *live* posture
    # over just the currently-active findings (excluding suppressed/resolved)
    # from the same PostureFactor shape (§6.4).
    composite = risk.account_posture_score(
        [
            risk.PostureFactor(
                severity=f.severity.value,
                blast_radius=(
                    p.blast_radius_score if (p := principals.get(f.principal_uid or "")) else 0
                ),
                is_escalation=bool(f.evidence.get("graph_path")),
            )
            for f in findings
        ]
    )

    return AnalysisResult(
        findings=findings,
        composite_score=composite,
        counts_by_severity=dict(counts_by_severity),
        counts_by_category=dict(counts_by_category),
        compliance_summary=compliance_summary,
        graph_edges=graph_result.edges,
    )


def _summarize_compliance(findings: list[Finding]) -> dict[str, dict[str, int]]:
    """Per-framework fail counts (a finding present == that control failing)."""
    summary: dict[str, dict[str, int]] = {}
    for finding in findings:
        for framework in frameworks_for(finding.check_id):
            bucket = summary.setdefault(framework, {"fail": 0})
            bucket["fail"] += 1
    return summary
