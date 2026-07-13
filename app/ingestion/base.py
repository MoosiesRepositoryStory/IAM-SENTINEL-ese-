"""Ingestion adapter interface + a simple progress reporter (§5.1)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class RawDataset:
    """Source-shaped payloads, before normalization into domain records."""

    principals: list[dict[str, Any]] = field(default_factory=list)
    policies: list[dict[str, Any]] = field(default_factory=list)
    log_events: list[dict[str, Any]] = field(default_factory=list)
    attachments: list[tuple[str, str]] = field(default_factory=list)


class ProgressReporter:
    """Reports scan progress. Phase 0 uses an in-process callback; Phase 2 swaps
    in a Redis-backed implementation with the same surface."""

    def __init__(self, callback: Callable[[int, str], None] | None = None) -> None:
        self._callback = callback
        self.pct = 0
        self.stage = "queued"

    def update(self, pct: int, stage: str) -> None:
        self.pct = max(0, min(100, pct))
        self.stage = stage
        if self._callback is not None:
            self._callback(self.pct, self.stage)


@runtime_checkable
class IngestionAdapter(Protocol):
    source_type: str

    def fetch(self, source_config: dict[str, Any], progress: ProgressReporter) -> RawDataset: ...


_ADAPTERS: dict[str, IngestionAdapter] = {}


def register_adapter(adapter: IngestionAdapter) -> IngestionAdapter:
    _ADAPTERS[adapter.source_type] = adapter
    return adapter


def get_adapter(source_type: str) -> IngestionAdapter:
    if source_type not in _ADAPTERS:
        raise KeyError(
            f"No ingestion adapter registered for source_type={source_type!r}. "
            f"Available: {sorted(_ADAPTERS)}"
        )
    return _ADAPTERS[source_type]


def available_adapters() -> list[str]:
    return sorted(_ADAPTERS)
