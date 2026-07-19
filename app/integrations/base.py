"""Ticket/notification integration abstraction (§7.5, Phase 4 Slice 5).

A single ``TicketAdapter`` Protocol so "create ticket" is one code path
regardless of destination — ``ticket_service`` never branches on ``kind``
itself, it just looks the adapter up in the registry (see ``registry.py``)
and calls ``create_ticket``. ``FindingView`` is a small, adapter-facing
projection of a finding (not the ORM row) so an adapter can't reach back into
the session/mutate anything it shouldn't — same decoupling principle as the
domain layer's own records (§3).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class FindingView:
    """Everything an adapter needs to describe the finding in a ticket —
    deliberately not the ORM ``FindingGroup``/``Finding`` rows themselves."""

    group_id: int
    check_id: str
    severity: str
    category: str
    principal_uid: str | None
    resource: str | None
    recommendation: str
    finding_url: str


@dataclass(frozen=True)
class TicketRef:
    """What creating a ticket produces. ``simulated`` is the honest signal a
    caller/UI can key off of (the ref TEXT also carries a human-readable
    " (simulated)" suffix per §7.5 — this field is for code, that suffix is
    for people). ``url`` is ``None`` when the adapter has no genuinely
    browsable link for what it just did (true for all three adapters here —
    see each module's docstring) rather than fabricating one."""

    ref: str
    simulated: bool
    url: str | None = None


class IntegrationError(RuntimeError):
    """Raised when a REAL integration attempt fails (currently only
    ``WebhookAdapter``, the one adapter that actually calls out) — a network
    error, a non-2xx response, or bad target config. Never raised for the
    Jira/Slack simulated path: returning a clearly-labeled simulated
    ``TicketRef`` *is* that path succeeding honestly, not a failure."""


class TicketAdapter(Protocol):
    kind: str

    def create_ticket(
        self, finding: FindingView, config: dict, *, title: str, body: str
    ) -> TicketRef: ...
