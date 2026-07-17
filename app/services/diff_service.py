"""Run-to-run diff (§5.4) — computed on demand, never stored.

The locked Phase 2 decision is **compute-on-demand, no new table**: a diff is a
pure function of two runs' already-persisted ``finding`` rows, so persisting it
would only add a cache to invalidate. Both runs' findings are a single indexed
query each (``ix_finding_run``), which is cheap enough that the diff view can
recompute on every request.

Identity across runs is the **fingerprint** (§4.5) — deliberately not the
finding's primary key, which is per-run, and not the title/evidence, which are
exactly what we want to detect changing. Fingerprints are carried on
``finding_group``, one row per fingerprint per account, so this joins through
the group rather than recomputing the hash.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding, FindingGroup, Run


class DiffError(RuntimeError):
    """The two runs can't be meaningfully diffed (missing, or different accounts)."""


@dataclass(frozen=True)
class EvidenceChange:
    key: str
    before: Any
    after: Any


@dataclass(frozen=True)
class FindingDelta:
    """What changed about one finding that is present in BOTH runs."""

    severity_before: str
    severity_after: str
    risk_before: int
    risk_after: int
    status_before: str
    status_after: str
    evidence_changes: tuple[EvidenceChange, ...]

    @property
    def severity_changed(self) -> bool:
        return self.severity_before != self.severity_after

    @property
    def risk_changed(self) -> bool:
        return self.risk_before != self.risk_after

    @property
    def status_changed(self) -> bool:
        return self.status_before != self.status_after

    @property
    def risk_delta(self) -> int:
        return self.risk_after - self.risk_before

    @property
    def has_changes(self) -> bool:
        return bool(
            self.severity_changed
            or self.risk_changed
            or self.status_changed
            or self.evidence_changes
        )


@dataclass(frozen=True)
class DiffCard:
    """One finding on the diff board. ``risk_score``/``severity`` describe the
    side the card is *about*: the newer run for new/changed, the older run for
    resolved (where there is no newer row to describe)."""

    fingerprint: str
    group_id: int
    check_id: str
    title: str
    severity: str
    category: str
    principal_uid: str | None
    risk_score: int
    delta: FindingDelta | None = None


@dataclass(frozen=True)
class RunDiff:
    run_a: Run  # older
    run_b: Run  # newer
    new: tuple[DiffCard, ...]
    changed: tuple[DiffCard, ...]
    resolved: tuple[DiffCard, ...]
    unchanged_count: int  # present in both AND identical — not shown as cards
    risk_before: int  # total risk across all of run_a's findings
    risk_after: int  # ...and run_b's

    @property
    def new_count(self) -> int:
        return len(self.new)

    @property
    def changed_count(self) -> int:
        return len(self.changed)

    @property
    def resolved_count(self) -> int:
        return len(self.resolved)

    @property
    def net_risk(self) -> int:
        """Signed total-risk movement (§8.9's "net risk +18"). Positive = the
        account got riskier. Derived from every finding in each run, not just
        the cards, so it still moves when a finding's risk changes."""
        return self.risk_after - self.risk_before

    @property
    def score_before(self) -> int | None:
        return self.run_a.composite_score

    @property
    def score_after(self) -> int | None:
        return self.run_b.composite_score

    @property
    def score_delta(self) -> int | None:
        if self.score_before is None or self.score_after is None:
            return None
        return self.score_after - self.score_before

    @property
    def is_empty(self) -> bool:
        return not (self.new or self.changed or self.resolved)


def _evidence_changes(
    before: dict[str, Any] | None, after: dict[str, Any] | None
) -> tuple[EvidenceChange, ...]:
    """Key-by-key evidence comparison over the union of both sides, so a key
    that appeared or vanished counts as a change (surfacing as None on the
    missing side) rather than being silently ignored.

    Rule-describing keys (``threshold``, ``window_days``) are deliberately NOT
    excluded: if they moved, someone re-scanned with different thresholds, and
    a finding whose evidence only changed because the rule changed is exactly
    the kind of thing an analyst should see rather than have hidden.
    """
    before = before or {}
    after = after or {}
    changes = [
        EvidenceChange(key=key, before=before.get(key), after=after.get(key))
        for key in sorted(set(before) | set(after))
        if before.get(key) != after.get(key)
    ]
    return tuple(changes)


def _delta(older: Finding, newer: Finding) -> FindingDelta:
    return FindingDelta(
        severity_before=older.severity,
        severity_after=newer.severity,
        risk_before=older.risk_score,
        risk_after=newer.risk_score,
        status_before=older.status,
        status_after=newer.status,
        evidence_changes=_evidence_changes(older.evidence, newer.evidence),
    )


def _card(finding: Finding, fingerprint: str, delta: FindingDelta | None = None) -> DiffCard:
    return DiffCard(
        fingerprint=fingerprint,
        group_id=finding.group_id,
        check_id=finding.check_id,
        title=finding.title,
        severity=finding.severity,
        category=finding.category,
        principal_uid=finding.principal_uid,
        risk_score=finding.risk_score,
        delta=delta,
    )


def _findings_by_fingerprint(session: Session, run_id: int) -> dict[str, Finding]:
    """All of a run's findings keyed by their group's fingerprint.

    A run emits at most one finding per fingerprint (``_persist_findings`` goes
    through ``_get_or_create_group``, which is unique on account+fingerprint),
    so building a plain dict here can't silently drop a row.
    """
    rows = session.execute(
        select(Finding, FindingGroup.fingerprint)
        .join(FindingGroup, FindingGroup.id == Finding.group_id)
        .where(Finding.run_id == run_id)
    ).all()
    return {fp: finding for finding, fp in rows}


def _by_risk(cards: list[DiffCard]) -> tuple[DiffCard, ...]:
    """Riskiest first; ties broken by title so the board is stable across
    requests (an unstable order would make the view flicker on reload)."""
    return tuple(sorted(cards, key=lambda c: (-c.risk_score, c.title)))


def diff(session: Session, run_a_id: int, run_b_id: int) -> RunDiff:
    """Diff two runs of the same account, **always oldest -> newest** (§5.4).

    The caller may pass the pair in either order: they are reordered by run id
    (monotonic, so it matches chronological order) before anything is computed.
    That way "new" always means "appeared in the later scan" regardless of how
    the URL was constructed.
    """
    run_a = session.get(Run, run_a_id)
    run_b = session.get(Run, run_b_id)
    if run_a is None or run_b is None:
        missing = run_a_id if run_a is None else run_b_id
        raise DiffError(f"Run {missing} not found.")
    if run_a.account_id != run_b.account_id:
        raise DiffError("Cannot diff runs from different accounts.")
    if run_a.id == run_b.id:
        raise DiffError("Cannot diff a run against itself.")
    if run_a.id > run_b.id:
        run_a, run_b = run_b, run_a

    older = _findings_by_fingerprint(session, run_a.id)
    newer = _findings_by_fingerprint(session, run_b.id)

    new_cards = [_card(newer[fp], fp) for fp in newer.keys() - older.keys()]
    resolved_cards = [_card(older[fp], fp) for fp in older.keys() - newer.keys()]

    changed_cards: list[DiffCard] = []
    unchanged_count = 0
    for fp in older.keys() & newer.keys():
        delta = _delta(older[fp], newer[fp])
        if delta.has_changes:
            changed_cards.append(_card(newer[fp], fp, delta))
        else:
            unchanged_count += 1

    return RunDiff(
        run_a=run_a,
        run_b=run_b,
        new=_by_risk(new_cards),
        changed=_by_risk(changed_cards),
        resolved=_by_risk(resolved_cards),
        unchanged_count=unchanged_count,
        risk_before=sum(f.risk_score for f in older.values()),
        risk_after=sum(f.risk_score for f in newer.values()),
    )


def default_diff_pair(session: Session, account_id: int) -> tuple[int, int] | None:
    """The (previous, latest) completed runs for an account — §8.9's default
    comparison. ``None`` when the account hasn't got two completed runs yet."""
    ids: Sequence[int] = session.scalars(
        select(Run.id)
        .where(Run.account_id == account_id, Run.status == "completed")
        .order_by(Run.id.desc())
        .limit(2)
    ).all()
    if len(ids) < 2:
        return None
    return ids[1], ids[0]
