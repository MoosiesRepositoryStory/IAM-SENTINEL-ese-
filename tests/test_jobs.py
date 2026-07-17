"""ThreadingJobQueue unit tests (§3.3.4, Phase 2 Slice 3 decision 1)."""

from __future__ import annotations

import threading
import time

from app.jobs import ThreadingJobQueue


def test_submit_returns_without_waiting_for_the_job() -> None:
    """submit() must not block the caller — the whole point of a job queue."""
    queue = ThreadingJobQueue()
    started = threading.Event()
    finish_line = threading.Event()

    def slow_job() -> None:
        started.set()
        finish_line.wait(timeout=5)

    t0 = time.monotonic()
    queue.submit(slow_job)
    elapsed = time.monotonic() - t0

    assert elapsed < 0.5, "submit() blocked waiting for the job to run"
    assert started.wait(timeout=2), "job never started on the background thread"
    finish_line.set()  # let the worker thread exit cleanly


def test_job_runs_on_a_different_thread_and_actually_completes() -> None:
    queue = ThreadingJobQueue()
    caller_thread = threading.get_ident()
    result: dict[str, object] = {}
    done = threading.Event()

    def job() -> None:
        result["thread"] = threading.get_ident()
        result["ran"] = True
        done.set()

    queue.submit(job)
    assert done.wait(timeout=5), "job did not complete in time"
    assert result["ran"] is True
    assert result["thread"] != caller_thread


def test_multiple_jobs_all_complete() -> None:
    queue = ThreadingJobQueue()
    n = 8
    done = threading.Event()
    completed: list[int] = []
    lock = threading.Lock()

    def make_job(i: int):  # noqa: ANN202
        def job() -> None:
            with lock:
                completed.append(i)
                if len(completed) == n:
                    done.set()

        return job

    for i in range(n):
        queue.submit(make_job(i))

    assert done.wait(timeout=5)
    assert sorted(completed) == list(range(n))
