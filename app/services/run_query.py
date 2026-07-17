"""Runs page + live-progress poll partial query support (§8.10, Phase 2 Slice 3)."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Account, Run


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


def list_runs(session: Session, *, limit: int = 50) -> list[RunRow]:
    """All runs across all accounts, newest first."""
    pairs = session.execute(
        select(Run, Account.name)
        .join(Account, Account.id == Run.account_id)
        .order_by(Run.id.desc())
        .limit(limit)
    ).all()
    return [_to_row(run, account_name) for run, account_name in pairs]


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
