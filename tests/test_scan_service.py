"""End-to-end scan integration tests (§12.2)."""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

import pytest
from app.db import session_scope
from app.jobs import get_job_queue, set_job_queue
from app.models import Finding, FindingGroup, Run, RunSummary
from app.services import create_account, enqueue_scan, run_scan
from app.services.scan_service import ScanError
from sqlalchemy import select

pytestmark = pytest.mark.integration

_SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def _scan_samples(session):
    account = create_account(
        session,
        name="Acme Corp",
        source_type="file",
        source_config={
            "inventory_path": str(_SAMPLES / "users.csv"),
            "policies_path": str(_SAMPLES / "policies.json"),
            "logs_path": str(_SAMPLES / "auth.log"),
        },
    )
    return run_scan(session, account.id)


def test_scan_completes_and_persists(db_session) -> None:
    run = _scan_samples(db_session)
    assert run.status == "completed"
    assert run.composite_score is not None
    assert run.duration_ms is not None

    findings = db_session.scalars(select(Finding).where(Finding.run_id == run.id)).all()
    assert len(findings) > 10

    summary = db_session.get(RunSummary, run.id)
    assert summary is not None
    assert summary.total_findings == len(findings)


def test_golden_escalation_finding_present(db_session) -> None:
    """The seeded intern must surface as a CRITICAL privilege-escalation finding."""
    run = _scan_samples(db_session)
    escalations = db_session.scalars(
        select(Finding).where(
            Finding.run_id == run.id,
            Finding.check_id == "iam.escalation.passrole_createkey",
        )
    ).all()
    intern = [f for f in escalations if f.principal_uid == "user/intern"]
    assert intern, "expected an escalation finding for the intern"
    assert intern[0].severity == "CRITICAL"


def test_findings_are_grouped_and_open(db_session) -> None:
    run = _scan_samples(db_session)
    groups = db_session.scalars(
        select(FindingGroup).where(FindingGroup.account_id == run.account_id)
    ).all()
    assert groups
    assert all(g.current_status == "open" for g in groups)


def test_rescan_reuses_finding_groups(db_session) -> None:
    """A second scan must correlate to the same groups (workflow continuity)."""
    run1 = _scan_samples(db_session)
    groups_after_1 = db_session.scalars(select(FindingGroup)).all()
    ids_1 = {g.id for g in groups_after_1}

    # Re-scan the same account.
    run2 = run_scan(db_session, run1.account_id)
    assert run2.id != run1.id
    groups_after_2 = db_session.scalars(select(FindingGroup)).all()
    ids_2 = {g.id for g in groups_after_2}

    # No new groups created for identical findings; all carried forward.
    assert ids_1 == ids_2
    for g in groups_after_2:
        assert g.last_seen_run == run2.id


# -- enqueue_scan / background execution (Phase 2 Slice 3, §3.3.4) ----------


class _RecordingJobQueue:
    """Captures submitted jobs without running them, so a test can assert what
    state exists *before* execution, then run the captured job itself."""

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


def _create_committed_file_account(session, name: str = "Acme Corp (async)"):
    account = create_account(
        session,
        name=name,
        source_type="file",
        source_config={
            "inventory_path": str(_SAMPLES / "users.csv"),
            "policies_path": str(_SAMPLES / "policies.json"),
            "logs_path": str(_SAMPLES / "auth.log"),
        },
    )
    # enqueue_scan opens its own session and must see this row already
    # committed — mirrors what the web routes do across two closed sessions.
    session.commit()
    return account


def test_enqueue_scan_returns_before_the_job_runs(db_session, job_queue_spy) -> None:
    """enqueue_scan creates a queued Run and hands it to the job queue WITHOUT
    running it inline — proven with a spy queue that records the submitted job
    instead of executing it: the Run is still `queued` and nothing has been
    persisted right after enqueue_scan returns. Running the captured job by
    hand is exactly what the background thread would do, and drives the same
    Run to completion — proving the submitted job really is the scan body."""
    account = _create_committed_file_account(db_session)
    run_id = enqueue_scan(account.id)

    assert len(job_queue_spy.jobs) == 1
    with session_scope() as session:
        run = session.get(Run, run_id)
        assert run is not None
        assert run.status == "queued"
        assert run.progress_pct == 0
        assert session.scalars(select(Finding).where(Finding.run_id == run_id)).first() is None

    job_queue_spy.jobs[0]()

    with session_scope() as session:
        run = session.get(Run, run_id)
        assert run is not None
        assert run.status == "completed"
        assert run.composite_score is not None


class _RejectingJobQueue:
    """Simulates a queue that refuses the job (pool exhausted/shut down) —
    submit() raises instead of accepting it."""

    def submit(self, fn: Callable[[], None]) -> None:
        raise RuntimeError("queue is shut down")


def test_enqueue_scan_marks_run_failed_when_submission_itself_fails(db_session) -> None:
    """Without a guard here, a queue that rejects the job leaves the Run
    permanently stuck `queued` — nothing would ever call execute_scan to move
    it out of that state, so a Runs-page poller would spin on a job that was
    never actually accepted. enqueue_scan must instead transition the row to
    `failed` and surface the failure to its own caller."""
    account = _create_committed_file_account(db_session, name="Acme Corp (rejected)")
    original = get_job_queue()
    set_job_queue(_RejectingJobQueue())
    try:
        with pytest.raises(ScanError, match="Failed to enqueue scan"):
            enqueue_scan(account.id)
    finally:
        set_job_queue(original)

    with session_scope() as session:
        run = session.scalars(select(Run).where(Run.account_id == account.id)).one()
        assert run.status == "failed"
        assert run.error_message is not None and "queue is shut down" in run.error_message
        assert run.finished_at is not None


def test_enqueue_scan_real_threading_executor_drives_it_to_completion(db_session) -> None:
    """End-to-end against the actual default ThreadingJobQueue (no spy): the
    scan genuinely runs on a background thread and eventually completes,
    observed only by polling a fresh session — the same thing the Runs page's
    htmx polling does over HTTP."""
    account = _create_committed_file_account(db_session, name="Acme Corp (real thread)")
    run_id = enqueue_scan(account.id)

    deadline = time.monotonic() + 10
    status: str | None = None
    while time.monotonic() < deadline:
        with session_scope() as session:
            run = session.get(Run, run_id)
            status = run.status if run is not None else None
        if status in ("completed", "failed"):
            break
        time.sleep(0.05)

    assert status == "completed"
    with session_scope() as session:
        summary = session.get(RunSummary, run_id)
        assert summary is not None
        assert summary.total_findings > 10
