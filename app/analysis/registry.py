"""The pluggable rule registry (§6.1).

Each check is a small class carrying a :class:`CheckMeta` and a ``run`` method
that yields :class:`~app.domain.records.Finding` objects from a shared
:class:`CheckContext`. Checks self-describe their compliance mapping and
remediation so the ``/checks`` catalog and compliance page are free.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from app.analysis.graph import GraphResult
from app.domain.enums import Category, Severity
from app.domain.records import Finding, NormalizedDataset, Thresholds


@dataclass(frozen=True)
class CheckMeta:
    id: str
    title: str
    category: Category
    default_severity: Severity
    description: str
    remediation: str
    compliance: list[str] = field(default_factory=list)


@dataclass
class ActivityIndex:
    """Actions actually observed per principal, derived from log events.

    ``used_actions`` holds normalized IAM ``service:Action`` strings for events
    with a confirmed ``outcome == "success"`` only (sign-in events, denied/
    failed attempts, and unknown/missing outcomes are all excluded), so it's
    directly comparable to a principal's *granted* actions for the
    least-privilege diff (§6.3).
    ``event_counts`` holds the total number of observed events per principal —
    including logins and denied attempts, i.e. any evidence the principal was
    actually captured in the logs — and drives both the "is this identity
    active at all?" signal and the recommendation-sufficiency gate. An empty
    index is valid and simply means activity-based checks emit nothing.
    """

    used_actions: dict[str, set[str]] = field(default_factory=dict)
    event_counts: dict[str, int] = field(default_factory=dict)
    window_days: int = 0

    def used_by(self, principal_uid: str) -> set[str]:
        return self.used_actions.get(principal_uid, set())

    def events_for(self, principal_uid: str) -> int:
        return self.event_counts.get(principal_uid, 0)

    def is_active(self, principal_uid: str) -> bool:
        """Whether we observed *any* activity for this principal (a successful
        API call, a login, or even a denied attempt — all mean the identity is
        live). Distinct from ``used_by`` emptiness: a login-only user is active
        but has no *policy actions* used."""
        return self.events_for(principal_uid) > 0


@dataclass
class CheckContext:
    """Everything a check needs, assembled once and shared across all checks."""

    dataset: NormalizedDataset
    thresholds: Thresholds
    activity: ActivityIndex = field(default_factory=ActivityIndex)
    graph: GraphResult = field(default_factory=GraphResult)


@runtime_checkable
class Check(Protocol):
    meta: CheckMeta

    def run(self, ctx: CheckContext) -> Iterable[Finding]: ...


REGISTRY: dict[str, Check] = {}


def register(check_cls: type) -> type:
    """Class decorator that instantiates and registers a check by ``meta.id``."""
    instance = check_cls()
    meta = instance.meta
    if meta.id in REGISTRY:
        raise ValueError(f"Duplicate check id registered: {meta.id}")
    REGISTRY[meta.id] = instance
    return check_cls


def get(check_id: str) -> Check:
    return REGISTRY[check_id]


def all_checks() -> list[Check]:
    return list(REGISTRY.values())
