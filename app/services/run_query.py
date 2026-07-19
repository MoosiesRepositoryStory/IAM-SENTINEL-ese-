"""Runs page + live-progress poll partial query support (§8.10, Phase 2 Slice 3)."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Account, Finding, Run


@dataclass
class RunRow:
    """One row for the Runs page: a run plus display-only plain fields (not
    relationship access) so the view can ``session.expunge(row.run)`` safely."""

    run: Run
    account_name: str
    total_findings: int | None
    critical_count: int | None


def _to_row(run: Run, account_name: str) -> RunRow:
    summary = run.summary
    return RunRow(
        run=run,
        account_name=account_name,
        total_findings=summary.total_findings if summary else None,
        critical_count=summary.count_critical if summary else None,
    )


def list_runs(session: Session, *, limit: int = 50, offset: int = 0) -> list[RunRow]:
    """All runs across all accounts, newest first. ``offset`` (added for the
    API read surface's ``?limit=&offset=`` pagination, Phase 4 Slice 4a) is
    unused by the HTML app's own caller, which never sets it, so behavior
    there is unchanged."""
    pairs = session.execute(
        select(Run, Account.name)
        .join(Account, Account.id == Run.account_id)
        .order_by(Run.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return [_to_row(run, account_name) for run, account_name in pairs]


def count_runs(session: Session) -> int:
    """Total runs across all accounts — the ``list_runs`` companion for
    ``X-Total-Count`` (Phase 4 Slice 4a)."""
    return session.scalar(select(func.count()).select_from(Run)) or 0


def list_run_findings(
    session: Session, run_id: int, *, limit: int = 50, offset: int = 0
) -> tuple[list[Finding], int]:
    """Every ``Finding`` snapshot from one specific run (as opposed to
    ``finding_query.query_findings``, which always means "the account's
    latest completed run") — the API's ``/runs/{id}/findings`` (Phase 4
    Slice 4a). Riskiest first, same order as the export path
    (``export_service._run_payload``)."""
    total = session.scalar(
        select(func.count()).select_from(Finding).where(Finding.run_id == run_id)
    ) or 0
    rows = list(
        session.scalars(
            select(Finding)
            .where(Finding.run_id == run_id)
            .order_by(Finding.risk_score.desc(), Finding.id.asc())
            .offset(offset)
            .limit(limit)
        )
    )
    return rows, total


def get_run_row(session: Session, run_id: int) -> RunRow | None:
    """A single row — the poll target for one Runs-page row's live progress."""
    run = session.get(Run, run_id)
    if run is None:
        return None
    account = session.get(Account, run.account_id)
    return _to_row(run, account.name if account is not None else "—")


@dataclass(frozen=True)
class ScorePoint:
    run_id: int
    score: int


def score_trend(session: Session, account_id: int, *, limit: int = 30) -> list[ScorePoint]:
    """Composite score per completed run, oldest -> newest — the §8.9 sparkline.

    Runs that completed without a score are skipped rather than plotted as 0,
    which would draw a fake cliff. Capped to the most recent ``limit`` runs and
    then re-sorted ascending, so a long history shows the recent trend rather
    than compressing everything into illegibility.
    """
    rows = session.execute(
        select(Run.id, Run.composite_score)
        .where(
            Run.account_id == account_id,
            Run.status == "completed",
            Run.composite_score.is_not(None),
        )
        .order_by(Run.id.desc())
        .limit(limit)
    ).all()
    return [ScorePoint(run_id=rid, score=score) for rid, score in reversed(rows)]
