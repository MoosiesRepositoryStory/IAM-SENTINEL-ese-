"""Adapter registry (§7.5) — maps an ``IntegrationTarget.kind`` to the
adapter class that implements it. Deliberately a plain dict (not the
decorator-based ``register()`` pattern ``app.analysis``/``app.ingestion``
use) — there are exactly three adapters, all built-in, none optional/extras-
gated, so there's no dynamic registration story to support yet.
"""

from __future__ import annotations

from app.integrations.base import TicketAdapter
from app.integrations.jira import JiraAdapter
from app.integrations.slack import SlackAdapter
from app.integrations.webhook import WebhookAdapter

ADAPTERS: dict[str, type[TicketAdapter]] = {
    "webhook": WebhookAdapter,
    "jira": JiraAdapter,
    "slack": SlackAdapter,
}

KINDS: tuple[str, ...] = tuple(ADAPTERS)


class UnknownIntegrationKind(ValueError):
    pass


def get_adapter(kind: str) -> TicketAdapter:
    try:
        return ADAPTERS[kind]()
    except KeyError:
        raise UnknownIntegrationKind(f"Unknown integration kind: {kind!r}") from None
