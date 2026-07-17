"""Cron expression parsing + next-fire-time computation (§5.5).

A pure wrapper around APScheduler's own ``CronTrigger`` — reused rather than
adding croniter as a second cron-parsing dependency. Lives in the domain layer
(no DB, no job queue) specifically so both ``app.scheduler`` (the live
APScheduler jobs) and ``app.services.schedule_service`` (CRUD validation) can
import it without depending on each other: ``scheduler`` needs services
(``enqueue_scan``, ``expire_exceptions``) to do its job, and if
``schedule_service`` also depended on ``app.scheduler`` for cron parsing, that
would be a genuine import cycle (``app.scheduler`` -> ``app.services`` package
init -> ``schedule_service`` -> ``app.scheduler``, still mid-import). Putting
the shared bit here — depended on by both, dependent on neither — is what
breaks it.
"""

from __future__ import annotations

from datetime import datetime

from apscheduler.triggers.cron import CronTrigger


def validate_cron(expr: str) -> CronTrigger:
    """Parse a 5-field cron expression, raising ``ValueError`` if invalid."""
    return CronTrigger.from_crontab(expr.strip())


def next_fire_iso(cron: str, *, now: datetime | None = None) -> str | None:
    """The next time ``cron`` fires after ``now`` (default: real now), as an
    ISO string — what the schedule-editor form and CRUD both display/store as
    ``next_run_at``."""
    trigger = validate_cron(cron)
    fire = trigger.get_next_fire_time(None, now or datetime.now(trigger.timezone))
    return fire.isoformat() if fire else None
