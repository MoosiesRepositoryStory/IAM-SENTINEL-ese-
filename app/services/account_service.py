"""Account creation + listing (used by the CLI, seed script, and the web app)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Account, Run


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


def list_accounts(session: Session) -> list[AccountRow]:
    """All accounts, newest first, each paired with its latest run."""
    accounts = session.scalars(select(Account).order_by(Account.id.desc())).all()
    rows: list[AccountRow] = []
    for account in accounts:
        latest = session.scalar(
            select(Run).where(Run.account_id == account.id).order_by(Run.id.desc())
        )
        summary = latest.summary if latest else None
        rows.append(
            AccountRow(
                account=account,
                latest_run=latest,
                total_findings=summary.total_findings if summary else None,
                critical_count=summary.count_critical if summary else None,
                composite_score=latest.composite_score if latest else None,
            )
        )
    return rows


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
