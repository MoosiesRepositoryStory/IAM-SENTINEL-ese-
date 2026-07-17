"""Recurring-scan schedule CRUD (§5.5 / §11.4, Slice 5).

One schedule per account — the UI treats "the account's recurring scan" as
singular (§11.4's account-settings "schedule config", not a schedule picker
list), so ``upsert_schedule`` replaces any existing row rather than a plain
insert. The schema's ``schedule.account_id`` foreign key would technically
allow several, but nothing in this app ever creates a second one.

Mirrors ``connect_service``'s split: this module only validates and mutates
the DB row. It deliberately does NOT import ``app.scheduler`` (both to avoid a
genuine import cycle — ``app.scheduler`` imports this package to reach
``enqueue_scan``/``expire_exceptions`` — and on principle: the caller
(``app/web/views.py``) calls ``sync_schedule``/``remove_schedule_job`` after
its ``session_scope`` block commits, the same "commit first, THEN touch the
background scheduler" discipline ``enqueue_scan`` documents and Slices 3-4
already follow). Cron parsing comes from ``app.domain.cron`` instead — a pure
helper both this module and ``app.scheduler`` depend on without depending on
each other.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.cron import next_fire_iso, validate_cron
from app.domain.records import Thresholds
from app.models import Schedule


class ScheduleError(ValueError):
    """An invalid cron expression or other bad schedule input."""


def get_schedule(session: Session, account_id: int) -> Schedule | None:
    return session.scalar(select(Schedule).where(Schedule.account_id == account_id))


def upsert_schedule(
    session: Session,
    *,
    account_id: int,
    cron: str,
    thresholds: Thresholds,
    enabled: bool = True,
    actor_id: int | None = None,
) -> Schedule:
    """Create the account's schedule, or update it in place if one exists.
    Raises :class:`ScheduleError` for an unparseable cron expression — checked
    before any row is touched, so a bad edit never leaves a half-applied one.
    """
    cron = (cron or "").strip()
    if not cron:
        raise ScheduleError("A cron expression is required.")
    try:
        validate_cron(cron)
    except ValueError as exc:
        raise ScheduleError(f"Invalid cron expression: {exc}") from exc

    schedule = get_schedule(session, account_id)
    next_run_at = next_fire_iso(cron) if enabled else None
    if schedule is None:
        schedule = Schedule(
            account_id=account_id,
            cron=cron,
            thresholds=thresholds.to_dict(),
            enabled=enabled,
            created_by=actor_id,
            next_run_at=next_run_at,
        )
        session.add(schedule)
    else:
        schedule.cron = cron
        schedule.thresholds = thresholds.to_dict()
        schedule.enabled = enabled
        schedule.next_run_at = next_run_at
    session.flush()
    return schedule


def delete_schedule(session: Session, account_id: int) -> int | None:
    """Delete the account's schedule, if any. Returns its id (the caller needs
    it to remove the matching APScheduler job after commit) or ``None``."""
    schedule = get_schedule(session, account_id)
    if schedule is None:
        return None
    schedule_id = schedule.id
    session.delete(schedule)
    session.flush()
    return schedule_id
