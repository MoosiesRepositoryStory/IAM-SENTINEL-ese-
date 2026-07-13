"""Account creation helper (used by the CLI, seed script, and later the API)."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models import Account


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
