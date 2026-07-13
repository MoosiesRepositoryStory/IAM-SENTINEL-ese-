"""ScanService — orchestrates one scan: ingest -> analyze -> persist (§3.2, §11).

Phase 0 runs synchronously in-process (``SYNC_JOBS``). Phase 2 wraps this same
``execute_scan`` body in an RQ job with Redis-backed progress; the persistence
and correlation logic here is unchanged by that move.
"""

from __future__ import annotations

import time
from collections import Counter

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis.engine import AnalysisResult, run_analysis
from app.domain.enums import RunStatus, Severity
from app.domain.fingerprint import fingerprint
from app.domain.records import NormalizedDataset, Thresholds
from app.domain.timeutil import to_iso
from app.ingestion import get_adapter, normalize
from app.ingestion.base import ProgressReporter
from app.models import (
    Account,
    Finding,
    FindingGroup,
    FindingStatusHistory,
    LogEvent,
    Policy,
    Principal,
    Run,
    RunSummary,
)
from app.models.base import now_iso


class ScanError(RuntimeError):
    """Raised when a scan fails; the Run row is marked ``failed`` first."""


def run_scan(
    session: Session,
    account_id: int,
    *,
    thresholds: Thresholds | None = None,
    trigger: str = "manual",
    triggered_by: int | None = None,
) -> Run:
    """Create and execute a scan for ``account_id``, returning the completed Run."""
    account = session.get(Account, account_id)
    if account is None:
        raise ScanError(f"Account {account_id} not found")

    thresholds = thresholds or Thresholds.from_dict(account.source_config or {})
    run = Run(
        account_id=account.id,
        status=RunStatus.QUEUED.value,
        trigger=trigger,
        triggered_by=triggered_by,
        thresholds=thresholds.to_dict(),
    )
    session.add(run)
    session.flush()

    def _progress(pct: int, stage: str) -> None:
        run.progress_pct = pct
        run.progress_stage = stage
        session.flush()

    reporter = ProgressReporter(_progress)
    started = time.monotonic()
    run.started_at = now_iso()

    try:
        dataset = _ingest(account, reporter)
        run.status = RunStatus.ANALYZING.value
        reporter.update(55, "Running checks")
        result = run_analysis(dataset, thresholds)

        reporter.update(85, "Persisting results")
        _persist_snapshot(session, run, dataset)
        _persist_findings(session, account, run, result)
        _persist_summary(session, account, run, result)

        run.composite_score = result.composite_score
        run.status = RunStatus.COMPLETED.value
        run.progress_pct = 100
        run.progress_stage = "completed"
    except Exception as exc:  # noqa: BLE001 — record failure, then re-raise wrapped.
        run.status = RunStatus.FAILED.value
        run.error_message = str(exc)
        run.finished_at = now_iso()
        session.flush()
        raise ScanError(str(exc)) from exc

    run.finished_at = now_iso()
    run.duration_ms = int((time.monotonic() - started) * 1000)
    session.flush()
    return run


def _ingest(account: Account, reporter: ProgressReporter) -> NormalizedDataset:
    adapter = get_adapter(account.source_type)
    raw = adapter.fetch(account.source_config or {}, reporter)
    return normalize(raw)


def _persist_snapshot(session: Session, run: Run, dataset: NormalizedDataset) -> None:
    for p in dataset.principals:
        session.add(
            Principal(
                run_id=run.id,
                principal_uid=p.principal_uid,
                kind=p.kind,
                username=p.username,
                email=p.email,
                arn=p.arn,
                role=p.role,
                account_type=p.account_type,
                active=p.active,
                console_access=p.console_access,
                mfa_enabled=p.mfa_enabled,
                last_login=to_iso(p.last_login),
                password_last_changed=to_iso(p.password_last_changed),
                access_key_age_days=p.access_key_age_days,
                attached_policy_ids=p.attached_policy_uids,
                blast_radius_score=p.blast_radius_score,
                reachable_actions=p.reachable_actions,
                reachable_sensitive=p.reachable_sensitive,
                raw=p.raw,
            )
        )
    for pol in dataset.policies:
        session.add(
            Policy(
                run_id=run.id,
                policy_uid=pol.policy_uid,
                name=pol.name,
                kind=pol.kind,
                document=pol.document,
                statement_count=pol.statement_count,
                has_wildcard_action=pol.has_wildcard_action,
                has_wildcard_resource=pol.has_wildcard_resource,
                uses_not_action=pol.uses_not_action,
            )
        )
    for ev in dataset.log_events:
        session.add(
            LogEvent(
                run_id=run.id,
                ts=to_iso(ev.ts),
                principal_uid=ev.principal_uid,
                source_ip=ev.source_ip,
                event_name=ev.event_name,
                event_source=ev.event_source,
                outcome=ev.outcome,
                is_privileged=ev.is_privileged,
                is_sensitive_iam=ev.is_sensitive_iam,
                raw=ev.raw,
            )
        )
    session.flush()


def _get_or_create_group(
    session: Session, account: Account, run: Run, fp: str, check_id: str, principal_uid: str | None
) -> FindingGroup:
    group = session.scalar(
        select(FindingGroup).where(
            FindingGroup.account_id == account.id, FindingGroup.fingerprint == fp
        )
    )
    if group is None:
        group = FindingGroup(
            account_id=account.id,
            fingerprint=fp,
            check_id=check_id,
            principal_uid=principal_uid,
            first_seen_run=run.id,
            last_seen_run=run.id,
            current_status="open",
        )
        session.add(group)
        session.flush()
        session.add(
            FindingStatusHistory(
                group_id=group.id,
                from_status=None,
                to_status="open",
                note="Detected",
            )
        )
    else:
        group.last_seen_run = run.id
        # Re-detection of a resolved issue reopens it (§7.1).
        if group.current_status == "resolved":
            session.add(
                FindingStatusHistory(
                    group_id=group.id,
                    from_status="resolved",
                    to_status="open",
                    note="Re-detected on new scan",
                )
            )
            group.current_status = "open"
    return group


def _persist_findings(session: Session, account: Account, run: Run, result: AnalysisResult) -> None:
    for f in result.findings:
        fp = fingerprint(f.check_id, f.principal_uid, f.resource, f.policy_uid)
        group = _get_or_create_group(session, account, run, fp, f.check_id, f.principal_uid)
        session.add(
            Finding(
                run_id=run.id,
                group_id=group.id,
                check_id=f.check_id,
                title=f.title,
                severity=f.severity.value,
                category=f.category.value,
                principal_uid=f.principal_uid,
                resource=f.resource,
                policy_uid=f.policy_uid,
                risk_score=f.risk_score,
                likelihood=f.likelihood,
                impact=f.impact,
                evidence=f.evidence,
                recommendation=f.recommendation,
                remediation_snippet=f.remediation_snippet,
                compliance_tags=f.compliance_tags,
                status=group.current_status,
            )
        )
    session.flush()


def _persist_summary(session: Session, account: Account, run: Run, result: AnalysisResult) -> None:
    sev = Counter(f.severity for f in result.findings)
    status_counts = Counter(
        g.current_status
        for g in session.scalars(select(FindingGroup).where(FindingGroup.last_seen_run == run.id))
    )
    prev_run = session.scalar(
        select(Run)
        .where(Run.account_id == account.id, Run.id != run.id, Run.status == "completed")
        .order_by(Run.id.desc())
    )
    new_count = resolved_count = None
    if prev_run is not None:
        prev_fps = _run_fingerprints(session, prev_run.id)
        cur_fps = _run_fingerprints(session, run.id)
        new_count = len(cur_fps - prev_fps)
        resolved_count = len(prev_fps - cur_fps)

    at_risk = len({f.principal_uid for f in result.findings if f.principal_uid})
    principals_total = session.scalar(
        select(func.count()).select_from(Principal).where(Principal.run_id == run.id)
    )
    session.add(
        RunSummary(
            run_id=run.id,
            total_findings=len(result.findings),
            count_low=sev.get(Severity.LOW, 0),
            count_medium=sev.get(Severity.MEDIUM, 0),
            count_high=sev.get(Severity.HIGH, 0),
            count_critical=sev.get(Severity.CRITICAL, 0),
            counts_by_category=result.counts_by_category,
            counts_by_status=dict(status_counts),
            compliance_summary=result.compliance_summary,
            new_count=new_count,
            resolved_count=resolved_count,
            principals_total=principals_total,
            principals_at_risk=at_risk,
        )
    )
    session.flush()


def _run_fingerprints(session: Session, run_id: int) -> set[str]:
    rows = session.scalars(select(Finding).where(Finding.run_id == run_id))
    return {fingerprint(f.check_id, f.principal_uid, f.resource, f.policy_uid) for f in rows}
