"""Background job execution seam (§3.3.4, Phase 2 Slice 3 decision 1).

The owner-approved plan is **in-process execution**: a ``ThreadingJobQueue``
(plain daemon-thread pool) is the only implementation built here. The RQ +
Redis path the spec eventually calls for — a separate ``rq worker`` process,
Redis-backed progress, multi-worker locking — is deliberately NOT built: a
demo/portfolio app has exactly one worker (the dev process itself), so a
thread pool gets identical "scan runs in the background, the UI polls for
progress" behavior with zero extra infrastructure. Swapping in RQ later means
writing a second ``JobQueue`` implementation against a Redis list + worker
process; call sites (``scan_service.enqueue_scan``) only see the protocol
below and would not change.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Protocol


class JobQueue(Protocol):
    def submit(self, fn: Callable[[], None]) -> None: ...


class ThreadingJobQueue:
    """Runs each job in a daemon thread from a small pool. In-process and not
    persisted across restarts — a queued-but-not-yet-picked-up job is lost if
    the dev server restarts, which is an acceptable trade for a single-worker
    demo app. A real deployment would swap this for an RQ-backed queue plus a
    separate worker process; nothing outside this module would need to change."""

    def __init__(self, max_workers: int = 4) -> None:
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="sentinel-job")

    def submit(self, fn: Callable[[], None]) -> None:
        self._pool.submit(fn)


_queue: JobQueue = ThreadingJobQueue()


def get_job_queue() -> JobQueue:
    return _queue


def set_job_queue(queue: JobQueue) -> None:
    """Test seam: swap in a queue that runs jobs inline (synchronously) for
    tests that don't want to deal with polling, or a spy that records what was
    submitted without running it."""
    global _queue
    _queue = queue
