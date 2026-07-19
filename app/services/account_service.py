"""Account creation + listing (used by the CLI, seed script, and the web app)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Account, Run, Schedule


@dataclass
class AccountRow:
    """One row for the Accounts page (§5.3): an account plus its latest run, if
    any has ever been executed. Plain fields (not relationship access) so the
    view can safely ``session.expunge`` before rendering."""

    account: Account
    latest_run: Run | None
    total_findings: int | None
    critical_count: int | None
    composite_score: int | None
    schedule: Schedule | None


def current_completed_run_id(session: Session) -> int | None:
    """The most recently completed run across every account — "latest scan,
    period" (§8.11's implicit account context). Shared by the HTML app
    (``app.web.views``) and the /api/v1 read surface (Phase 4 Slice 4a) so
    both mean the same thing by "the current run" without duplicating the
    query."""
    return session.scalar(select(Run.id).where(Run.status == "completed").order_by(Run.id.desc()))


def current_account(session: Session) -> Account | None:
    """No account switcher exists yet (Phase 2 Slice 2) — "current" means the
    account behind the most recently *completed* run (whatever was just
    connected or re-scanned), falling back to the newest-created account if
    nothing has been scanned yet. Shared by the HTML app and the API read
    surface for the same reason as :func:`current_completed_run_id`."""
    run_id = current_completed_run_id(session)
    if run_id is not None:
        run = session.get(Run, run_id)
        return session.get(Account, run.account_id) if run is not None else None
    return session.scalar(select(Account).order_by(Account.id.desc()))


def list_accounts(
    session: Session, *, limit: int | None = None, offset: int = 0
) -> list[AccountRow]:
    """All accounts, newest first, each paired with its latest run and its
    recurring-scan schedule, if any (§11.4's accounts-list "schedule badge").
    ``limit``/``offset`` (added for the API read surface's pagination, Phase
    4 Slice 4a) default to "everything" — the HTML app's own caller never
    sets them, so its behavior is unchanged."""
    stmt = select(Account).order_by(Account.id.desc()).offset(offset)
    if limit is not None:
        stmt = stmt.limit(limit)
    accounts = session.scalars(stmt).all()
    rows: list[AccountRow] = []
    for account in accounts:
        latest = session.scalar(
            select(Run).where(Run.account_id == account.id).order_by(Run.id.desc())
        )
        summary = latest.summary if latest else None
        schedule = session.scalar(select(Schedule).where(Schedule.account_id == account.id))
        rows.append(
            AccountRow(
                account=account,
                latest_run=latest,
                total_findings=summary.total_findings if summary else None,
                critical_count=summary.count_critical if summary else None,
                composite_score=latest.composite_score if latest else None,
                schedule=schedule,
            )
        )
    return rows


def count_accounts(session: Session) -> int:
    """Total accounts — the ``list_accounts`` companion for ``X-Total-Count``
    (Phase 4 Slice 4a)."""
    return session.scalar(select(func.count()).select_from(Account)) or 0


def create_account(
    session: Session,
    *,
    name: str,
    source_type: str,
    provider: str = "aws",
    external_id: str | None = None,
    source_config: dict[str, Any] | None = None,
    created_by: int | None = None,
) -> Account:
    account = Account(
        name=name,
        provider=provider,
        external_id=external_id,
        source_type=source_type,
        source_config=source_config or {},
        created_by=created_by,
    )
    session.add(account)
    session.flush()  # assign id without ending the transaction
    return account
