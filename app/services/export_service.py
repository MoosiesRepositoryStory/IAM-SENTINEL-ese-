"""Export a run's findings to JSON / CSV (the original tool's export path)."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding, Run, RunSummary


def _run_payload(session: Session, run_id: int) -> dict[str, Any]:
    run = session.get(Run, run_id)
    if run is None:
        raise ValueError(f"Run {run_id} not found")
    summary = session.get(RunSummary, run_id)
    findings = session.scalars(
        select(Finding).where(Finding.run_id == run_id).order_by(Finding.risk_score.desc())
    ).all()
    return {
        "run": {
            "id": run.id,
            "account_id": run.account_id,
            "status": run.status,
            "trigger": run.trigger,
            "composite_score": run.composite_score,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "duration_ms": run.duration_ms,
        },
        "summary": {
            "total_findings": summary.total_findings if summary else 0,
            "count_low": summary.count_low if summary else 0,
            "count_medium": summary.count_medium if summary else 0,
            "count_high": summary.count_high if summary else 0,
            "count_critical": summary.count_critical if summary else 0,
            "compliance_summary": summary.compliance_summary if summary else {},
        },
        "findings": [_finding_dict(f) for f in findings],
    }


def _finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id,
        "group_id": f.group_id,
        "check_id": f.check_id,
        "title": f.title,
        "severity": f.severity,
        "category": f.category,
        "status": f.status,
        "risk_score": f.risk_score,
        "likelihood": f.likelihood,
        "impact": f.impact,
        "principal_uid": f.principal_uid,
        "resource": f.resource,
        "policy_uid": f.policy_uid,
        "compliance_tags": f.compliance_tags or [],
        "recommendation": f.recommendation,
        "remediation_snippet": f.remediation_snippet,
        "evidence": f.evidence,
    }


def run_to_json(session: Session, run_id: int, *, indent: int = 2) -> str:
    return json.dumps(_run_payload(session, run_id), indent=indent, default=str)


def run_to_csv(session: Session, run_id: int) -> str:
    findings = session.scalars(
        select(Finding).where(Finding.run_id == run_id).order_by(Finding.risk_score.desc())
    ).all()
    buf = io.StringIO()
    columns = [
        "check_id",
        "title",
        "severity",
        "category",
        "status",
        "risk_score",
        "principal_uid",
        "resource",
        "policy_uid",
        "compliance_tags",
        "recommendation",
    ]
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        row = _finding_dict(f)
        row["compliance_tags"] = ";".join(row["compliance_tags"])
        writer.writerow(row)
    return buf.getvalue()
