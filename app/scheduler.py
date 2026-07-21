"""In-process recurring-scan + exception-expiry scheduler (§5.5 / §11.4, Slice 5).

Continues Slice 3's in-process posture (see ``app.jobs``): a single
APScheduler ``BackgroundScheduler`` running inside the same process as the web
app is the only implementation built here. The spec's "runs in a dedicated
worker process, not the web process, to avoid duplicate firing under Gunicorn
workers" plus a Redis ``SETNX`` lock against multi-process double-fire are
deliberately NOT built: this demo/portfolio app has exactly one process, so
there is no second worker to duplicate-fire against. A real multi-process
deployment would move ``start_scheduler()`` into a dedicated worker entrypoint
and wrap ``fire_schedule`` in the Redis lock; nothing else here would change.

Two kinds of recurring job share one scheduler instance:

- **Per-schedule cron jobs** (§5.5): one job per enabled ``schedule`` row,
  calling :func:`fire_schedule`. Schedule CRUD (``schedule_service``) calls
  :func:`sync_schedule` / :func:`remove_schedule_job` right after each commit
  so the live scheduler always mirrors the DB — this app's single-process
  analogue of the spec's Redis-pub/sub "reload on schedule CRUD" watcher,
  since there is only one process to notify.
- **The daily exception-expiry job** (§7.4 / §11.4): promotes Slice 2c's
  opportunistic on-read ``expire_exceptions`` call to a real recurring job.
  The on-read call in ``app/web/views.py`` is deliberately left in place as a
  belt-and-suspenders fallback — if the scheduler thread were ever down, a
  user opening the findings table still re-surfaces expired exceptions.
"""

from __future__ import annotations

import logging
from datetime import date

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select

from app.db import session_scope
from app.domain.cron import next_fire_iso, validate_cron
from app.domain.records import Thresholds
from app.models import Schedule
from app.models.base import now_iso
from app.services.exception_service import expire_exceptions
from app.services.scan_service import enqueue_scan

__all__ = [
    "EXPIRE_JOB_ID",
    "fire_schedule",
    "get_scheduler",
    "next_fire_iso",
    "remove_schedule_job",
    "run_expire_exceptions_job",
    "set_scheduler",
    "start_scheduler",
    "sync_schedule",
    "validate_cron",
]

logger = logging.getLogger(__name__)

EXPIRE_JOB_ID = "expire_exceptions_daily"
# 02:00 local server time — an arbitrary low-traffic hour; the spec (§7.4)
# only specifies "daily", not a time of day.
_EXPIRE_HOUR = 2

_scheduler: BackgroundScheduler | None = None


def get_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler()
    return _scheduler


def set_scheduler(scheduler: BackgroundScheduler) -> None:
    """Test seam: swap in a fresh (or pre-configured) scheduler instance
    without touching call sites — the same shape as ``app.jobs.set_job_queue``."""
    global _scheduler
    _scheduler = scheduler


def _schedule_job_id(schedule_id: int) -> str:
    return f"schedule:{schedule_id}"


def fire_schedule(schedule_id: int) -> int | None:
    """Run one schedule's scan: enqueue it and advance ``last_run_at`` /
    ``next_run_at``. This is both the APScheduler cron job body AND the
    "Run now" manual-override handler — a manual run doesn't shift the cron's
    own cadence (``next_run_at`` is always just "what the cron says is next as
    of now", independent of who triggered this call), so one function serves
    both without special-casing.

    Returns the new run's id, or ``None`` if the schedule was deleted or
    disabled since this fire was registered (a real race with "delete this
    schedule" that a stale APScheduler job could otherwise hit).
    """
    with session_scope() as session:
        schedule = session.get(Schedule, schedule_id)
        if schedule is None or not schedule.enabled:
            logger.info("Skipping fire for missing/disabled schedule %s", schedule_id)
            return None
        account_id = schedule.account_id
        created_by = schedule.created_by
        thresholds = Thresholds.from_dict(schedule.thresholds)
        schedule.last_run_at = now_iso()
        schedule.next_run_at = next_fire_iso(schedule.cron)

    # Outside the `with` block: the schedule's own row is already committed,
    # and enqueue_scan owns its own session + hands execution to a worker
    # thread that needs to see an already-durable Account row (same discipline
    # the Connect wizard and "Scan now" follow since Slice 3).
    return enqueue_scan(
        account_id, thresholds=thresholds, trigger="scheduled", triggered_by=created_by
    )


def _register_schedule_job(scheduler: BackgroundScheduler, schedule_id: int, cron: str) -> None:
    scheduler.add_job(
        fire_schedule,
        validate_cron(cron),
        args=[schedule_id],
        id=_schedule_job_id(schedule_id),
        replace_existing=True,
    )


def sync_schedule(schedule_id: int, *, cron: str, enabled: bool) -> None:
    """Add/update (or remove) ``schedule_id``'s APScheduler job to match its
    current cron/enabled state. Called by ``schedule_service`` right after
    every create/update/delete commits."""
    if not enabled:
        remove_schedule_job(schedule_id)
        return
    _register_schedule_job(get_scheduler(), schedule_id, cron)


def remove_schedule_job(schedule_id: int) -> None:
    scheduler = get_scheduler()
    if scheduler.get_job(_schedule_job_id(schedule_id)) is not None:
        scheduler.remove_job(_schedule_job_id(schedule_id))


def run_expire_exceptions_job(*, today: date | None = None) -> list[int]:
    """The daily job body — thinly wraps ``expire_exceptions`` in its own
    session. Keeps the exact ``today=`` override Slice 2c's tests already use
    (real APScheduler firing is never exercised in tests; this function is
    called directly with a controlled date instead, precisely so promoting
    the on-read check to a real job didn't require inventing a new testing
    strategy)."""
    with session_scope() as session:
        return expire_exceptions(session, today=today)


def start_scheduler() -> None:
    """Load every enabled schedule from the DB, register its cron job plus the
    daily expiry job, and start the scheduler thread. Idempotent — a second
    call (e.g. if ``create_app()`` ever runs twice in one process) is a no-op
    rather than raising APScheduler's ``SchedulerAlreadyRunningError``."""
    scheduler = get_scheduler()
    if scheduler.running:
        return
    with session_scope() as session:
        rows = [
            (s.id, s.cron)
            for s in session.scalars(select(Schedule).where(Schedule.enabled.is_(True)))
        ]
    for schedule_id, cron in rows:
        _register_schedule_job(scheduler, schedule_id, cron)
    scheduler.add_job(
        run_expire_exceptions_job,
        CronTrigger(hour=_EXPIRE_HOUR, minute=0),
        id=EXPIRE_JOB_ID,
        replace_existing=True,
    )
    scheduler.start()
    logger.info("Scheduler started: %d schedule(s) + daily exception-expiry job", len(rows))
