"""Scheduler tests (§5.5 / §11.4, Slice 5).

Two different testing strategies, deliberately:

- Most of this file calls ``fire_schedule``/``run_expire_exceptions_job``
  directly with a recording job queue and/or a ``today=`` override — the same
  wall-clock-free approach Slice 2c (exception expiry) and Slice 3
  (``job_queue_spy`` in ``test_scan_service.py``) already established. This
  covers "does firing a schedule actually enqueue+run a scan" and "does the
  daily job actually reopen an expired exception" with zero timing dependence.
- ``test_a_real_short_interval_trigger_actually_fires_the_job`` and
  ``test_a_real_scheduled_scan_fires_end_to_end_on_a_running_scheduler`` are
  the exception: they register a genuine ``BackgroundScheduler`` job on a very
  short interval and wait (bounded, via a deadline poll / ``threading.Event``,
  not a sleep loop) for it to fire on its own thread — proving the APScheduler
  wiring itself works, not just the function it calls.

Session discipline: ``fire_schedule``/``run_expire_exceptions_job`` each open
their OWN ``session_scope()`` (they must — a real APScheduler thread has no
caller session to reuse). Reading their effects back through the ``db_session``
fixture's own session would return a stale, un-refreshed identity-map copy, so
every post-condition read below goes through a fresh ``session_scope()``,
exactly like ``test_scan_service.py``'s own ``enqueue_scan`` tests do.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import date
from pathlib import Path

import pytest
from app.db import session_scope
from app.domain.records import Thresholds
from app.jobs import get_job_queue, set_job_queue
from app.models import AppUser, Finding, FindingException, FindingGroup, Run, Schedule
from app.scheduler import (
    EXPIRE_JOB_ID,
    fire_schedule,
    get_scheduler,
    next_fire_iso,
    remove_schedule_job,
    run_expire_exceptions_job,
    set_scheduler,
    start_scheduler,
    sync_schedule,
    validate_cron,
)
from app.services import create_account, run_scan
from app.services.exception_service import create_exception
from app.services.schedule_service import upsert_schedule
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select

pytestmark = pytest.mark.integration

_SAMPLES = Path(__file__).resolve().parent.parent / "samples"


# -- test-only job queue (mirrors test_scan_service.py's job_queue_spy) ------


class _RecordingJobQueue:
    def __init__(self) -> None:
        self.jobs: list[Callable[[], None]] = []

    def submit(self, fn: Callable[[], None]) -> None:
        self.jobs.append(fn)


@pytest.fixture
def job_queue_spy():
    original = get_job_queue()
    spy = _RecordingJobQueue()
    set_job_queue(spy)
    try:
        yield spy
    finally:
        set_job_queue(original)


@pytest.fixture
def fresh_scheduler():
    """An isolated, unstarted BackgroundScheduler per test, so tests can add/
    remove jobs without leaking state into each other via the module-level
    singleton. Always shut down, even one that was never started (APScheduler
    tolerates that)."""
    original = get_scheduler()
    scheduler = BackgroundScheduler()
    set_scheduler(scheduler)
    try:
        yield scheduler
    finally:
        # shutdown() itself raises SchedulerNotRunningError for a scheduler
        # that was never started — most tests here never call start_scheduler.
        if scheduler.running:
            scheduler.shutdown(wait=False)
        set_scheduler(original)


def _committed_schedule(
    session, *, cron: str = "0 2 * * *", enabled: bool = True
) -> tuple[int, int]:
    """Returns (schedule_id, account_id) rather than the ORM object — every
    caller needs these across a session boundary anyway, and passing plain
    ints sidesteps any temptation to read stale attributes off a detached
    instance."""
    account = create_account(session, name="Acme (sched)", source_type="moto_aws", source_config={})
    schedule = upsert_schedule(
        session, account_id=account.id, cron=cron, thresholds=Thresholds(), enabled=enabled
    )
    session.commit()  # fire_schedule/APScheduler read this from a fresh session/thread
    return schedule.id, account.id


# -- cron validation ----------------------------------------------------------


def test_validate_cron_accepts_a_well_formed_expression() -> None:
    validate_cron("0 2 * * *")  # must not raise


def test_validate_cron_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        validate_cron("not a cron expression")


def test_next_fire_iso_computes_the_next_occurrence_after_now() -> None:
    from datetime import datetime

    now = datetime(2026, 1, 1, 1, 0, 0)
    fire = next_fire_iso("0 2 * * *", now=now)
    assert fire is not None
    assert fire.startswith("2026-01-01T02:00:00")


# -- fire_schedule (the cron job body + "Run now") ---------------------------


def test_fire_schedule_enqueues_a_scheduled_scan_and_advances_last_next_run(
    db_session, job_queue_spy
) -> None:
    schedule_id, _account_id = _committed_schedule(db_session)
    with session_scope() as session:
        before_next_run_at = session.get(Schedule, schedule_id).next_run_at

    run_id = fire_schedule(schedule_id)

    assert run_id is not None
    assert len(job_queue_spy.jobs) == 1  # enqueue_scan submitted a job, didn't run it inline
    with session_scope() as session:
        run = session.get(Run, run_id)
        assert run.status == "queued"
        assert run.trigger == "scheduled"

        schedule = session.get(Schedule, schedule_id)
        assert schedule.last_run_at is not None
        assert schedule.next_run_at is not None
        # A real cron's next fire time doesn't depend on when it last fired,
        # only on the cron expression + now — recomputing must not regress it.
        assert schedule.next_run_at >= before_next_run_at

    # Running the captured job drives it to completion, same as a real
    # background thread would.
    job_queue_spy.jobs[0]()
    with session_scope() as session:
        assert session.get(Run, run_id).status == "completed"


def test_fire_schedule_returns_none_and_enqueues_nothing_for_a_disabled_schedule(
    db_session, job_queue_spy
) -> None:
    schedule_id, _account_id = _committed_schedule(db_session, enabled=False)

    result = fire_schedule(schedule_id)

    assert result is None
    assert job_queue_spy.jobs == []


def test_fire_schedule_returns_none_for_a_deleted_schedule(job_queue_spy) -> None:
    """Guards the race a stale APScheduler job could hit: the schedule row is
    gone (deleted between register and fire) by the time the job body runs."""
    assert fire_schedule(999999) is None
    assert job_queue_spy.jobs == []


def test_run_now_reuses_fire_schedule_and_does_not_shift_the_cron_cadence(
    db_session, job_queue_spy
) -> None:
    """The "Run now" override and the real cron trigger are the SAME function
    — a manual run must not perturb next_run_at beyond what the cron itself
    would already say is next."""
    schedule_id, _account_id = _committed_schedule(db_session, cron="0 2 * * *")
    expected_next = next_fire_iso("0 2 * * *")

    fire_schedule(schedule_id)

    with session_scope() as session:
        assert session.get(Schedule, schedule_id).next_run_at == expected_next


# -- scheduler <-> DB sync (schedule_service calls these after every commit) --


def test_sync_schedule_registers_a_job_for_an_enabled_schedule(db_session, fresh_scheduler) -> None:
    schedule_id, _account_id = _committed_schedule(db_session, cron="*/5 * * * *")

    sync_schedule(schedule_id, cron="*/5 * * * *", enabled=True)

    assert fresh_scheduler.get_job(f"schedule:{schedule_id}") is not None


def test_sync_schedule_removes_the_job_when_disabled(db_session, fresh_scheduler) -> None:
    schedule_id, _account_id = _committed_schedule(db_session, cron="*/5 * * * *")
    sync_schedule(schedule_id, cron="*/5 * * * *", enabled=True)
    assert fresh_scheduler.get_job(f"schedule:{schedule_id}") is not None

    sync_schedule(schedule_id, cron="*/5 * * * *", enabled=False)

    assert fresh_scheduler.get_job(f"schedule:{schedule_id}") is None


def test_remove_schedule_job_is_safe_when_no_job_was_ever_registered(fresh_scheduler) -> None:
    remove_schedule_job(123456)  # must not raise


def test_start_scheduler_registers_every_enabled_schedule_plus_the_daily_expiry_job(
    db_session, fresh_scheduler
) -> None:
    enabled_id, _ = _committed_schedule(db_session, cron="0 2 * * *")
    disabled_id, _ = _committed_schedule(db_session, cron="0 3 * * *", enabled=False)

    start_scheduler()

    assert fresh_scheduler.get_job(f"schedule:{enabled_id}") is not None
    assert fresh_scheduler.get_job(f"schedule:{disabled_id}") is None
    assert fresh_scheduler.get_job(EXPIRE_JOB_ID) is not None
    assert fresh_scheduler.running


def test_start_scheduler_is_idempotent(fresh_scheduler) -> None:
    start_scheduler()
    start_scheduler()  # must not raise SchedulerAlreadyRunningError
    assert fresh_scheduler.running


# -- daily exception-expiry job (promotes Slice 2c's on-read check) ----------


def _scan_and_group_id(session) -> int:
    account = create_account(
        session,
        name="Acme (expiry)",
        source_type="file",
        source_config={
            "inventory_path": str(_SAMPLES / "users.csv"),
            "policies_path": str(_SAMPLES / "policies.json"),
            "logs_path": str(_SAMPLES / "auth.log"),
        },
    )
    run = run_scan(session, account.id)
    finding = session.scalars(select(Finding).where(Finding.run_id == run.id)).first()
    return finding.group_id


def _actor_id(session) -> int:
    user = AppUser(
        email="sched-test@iam-sentinel.local",
        display_name="Test Actor",
        password_hash="!",
        role="admin",
    )
    session.add(user)
    session.flush()
    return user.id


def test_run_expire_exceptions_job_reopens_an_expired_exception_via_today_override(
    db_session,
) -> None:
    """The exact Slice 2c testing strategy, reused: force ``today`` past the
    expiry rather than waiting for the real daily trigger or faking the wall
    clock."""
    group_id = _scan_and_group_id(db_session)
    group = db_session.get(FindingGroup, group_id)
    create_exception(
        db_session,
        group,
        kind="accepted_risk",
        reason="temporary",
        actor_id=_actor_id(db_session),
        expires_at="2020-01-01",
    )
    db_session.commit()

    reopened = run_expire_exceptions_job(today=date(2026, 1, 1))

    assert group_id in reopened
    with session_scope() as session:
        assert session.get(FindingGroup, group_id).current_status == "open"
        exceptions = session.scalars(
            select(FindingException).where(FindingException.group_id == group_id)
        ).all()
        assert all(e.revoked_at is not None for e in exceptions)


def test_run_expire_exceptions_job_is_a_no_op_before_expiry(db_session) -> None:
    group_id = _scan_and_group_id(db_session)
    group = db_session.get(FindingGroup, group_id)
    create_exception(
        db_session,
        group,
        kind="accepted_risk",
        reason="temporary",
        actor_id=_actor_id(db_session),
        expires_at="2099-01-01",
    )
    db_session.commit()

    reopened = run_expire_exceptions_job(today=date(2026, 1, 1))

    assert reopened == []
    with session_scope() as session:
        assert session.get(FindingGroup, group_id).current_status == "accepted_risk"


# -- the one real-timing tests: prove the scheduler thread itself fires -----


def test_a_real_short_interval_trigger_actually_fires_the_job(fresh_scheduler) -> None:
    """Bypasses cron (whose minimum granularity is a minute) to prove the
    ACTUAL BackgroundScheduler thread invokes a registered job on its own —
    not just that the job function works when called directly, which every
    other test in this file already covers without any waiting."""
    fired = threading.Event()
    calls: list[int] = []

    def _job() -> None:
        calls.append(1)
        fired.set()

    fresh_scheduler.add_job(_job, IntervalTrigger(seconds=1), id="test-short-interval")
    assert not fresh_scheduler.running
    fresh_scheduler.start()

    assert fired.wait(timeout=5), "the scheduler thread never fired the job"
    assert len(calls) >= 1


def test_a_real_scheduled_scan_fires_end_to_end_on_a_running_scheduler(
    db_session, fresh_scheduler
) -> None:
    """One level closer to production than the job-queue-spy tests above:
    registers ``fire_schedule`` itself (not a stand-in) on a short interval and
    lets the REAL default ThreadingJobQueue run the scan — proving the whole
    chain (APScheduler thread -> fire_schedule -> enqueue_scan -> background
    scan thread) end to end, bounded by a short poll rather than cron's
    minute-level granularity."""
    schedule_id, account_id = _committed_schedule(db_session, cron="0 2 * * *")  # cron unused here

    fresh_scheduler.add_job(
        fire_schedule, IntervalTrigger(seconds=1), args=[schedule_id], id="test-fire-real"
    )
    fresh_scheduler.start()

    deadline = time.monotonic() + 15
    found = False
    while time.monotonic() < deadline:
        with session_scope() as session:
            found = (
                session.scalar(
                    select(Run.id).where(Run.account_id == account_id, Run.trigger == "scheduled")
                )
                is not None
            )
        if found:
            break
        time.sleep(0.2)

    fresh_scheduler.remove_job("test-fire-real")
    assert found, "no scheduled run appeared within the timeout"
