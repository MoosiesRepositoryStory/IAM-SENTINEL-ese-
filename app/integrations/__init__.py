"""Ticket/notification integration abstraction (§7.5, Phase 4 Slice 5).

One ``TicketAdapter`` Protocol, three built-in adapters (webhook = real,
jira/slack = permanent honest stubs — see each module's docstring for why),
looked up by kind through :data:`registry.ADAPTERS`.
"""

from app.integrations.base import FindingView, IntegrationError, TicketAdapter, TicketRef
from app.integrations.registry import KINDS, UnknownIntegrationKind, get_adapter

__all__ = [
    "KINDS",
    "FindingView",
    "IntegrationError",
    "TicketAdapter",
    "TicketRef",
    "UnknownIntegrationKind",
    "get_adapter",
]
