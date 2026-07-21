""" "Create ticket" orchestration (§7.5, Phase 4 Slice 5): resolves the chosen
``IntegrationTarget``, builds the adapter-facing ``FindingView``, calls the
right adapter (via ``app.integrations.registry``), and persists the returned
``TicketRef`` onto the finding group plus an audit-trail entry — the same
"validate/act/audit" shape ``workflow_service.transition`` and
``exception_service.create_exception`` already establish.

Framework-agnostic like every other service here: ``finding_url`` (the deep
link a ticket/message should point back at) is passed in by the caller
(``app.web.views``/``app.api.findings``, which have ``url_for``), not built
here.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.integrations.base import FindingView
from app.integrations.registry import get_adapter
from app.models import AuditEvent, Finding, FindingGroup, IntegrationTarget


class TicketError(ValueError):
    """Bad input or an unusable target: empty title, unknown/disabled
    target. Distinct from :class:`IntegrationError`, which is the adapter
    itself failing to actually deliver (currently only possible for the
    real ``WebhookAdapter``) — both are surfaced to the caller as a 400/502-
    style error, but they mean different things: this is "you asked for
    something that doesn't make sense," that is "the target didn't answer.\""""


def create_ticket(
    session: Session,
    group: FindingGroup,
    finding: Finding,
    *,
    target_id: int,
    title: str,
    body: str,
    finding_url: str,
    actor_id: int | None = None,
) -> IntegrationTarget:
    """Returns the ``IntegrationTarget`` used (for logging/UI convenience);
    the created ``TicketRef`` is already persisted onto ``group.ticket_ref``/
    ``group.ticket_url`` by the time this returns, which is what callers
    actually read back (via a fresh ``get_finding_detail``, same pattern
    every other mutation in this app follows)."""
    clean_title = (title or "").strip()
    if not clean_title:
        raise TicketError("A title is required.")
    clean_body = (body or "").strip()

    if group.ticket_ref:
        # A retry (double-click, client timeout on a request that actually
        # succeeded server-side, etc.) must not call the adapter a second
        # time — that would create a genuine second ticket in the external
        # system, and the group.ticket_ref assignment below would silently
        # overwrite the first one's reference, orphaning it with no link
        # back from this app.
        raise TicketError(f"A ticket already exists for this finding ({group.ticket_ref!r}).")

    target = session.get(IntegrationTarget, target_id)
    if target is None:
        raise TicketError("Integration target not found.")
    if not target.enabled:
        raise TicketError(f"{target.name!r} is disabled.")

    view = FindingView(
        group_id=group.id,
        check_id=finding.check_id,
        severity=finding.severity,
        category=finding.category,
        principal_uid=finding.principal_uid,
        resource=finding.resource,
        recommendation=finding.recommendation,
        finding_url=finding_url,
    )
    adapter = get_adapter(target.kind)
    # May raise IntegrationError (currently only WebhookAdapter can) — left
    # to propagate uncaught so the caller can tell "target unreachable"
    # apart from this function's own TicketError ("bad input").
    ref = adapter.create_ticket(view, target.config, title=clean_title, body=clean_body)

    group.ticket_ref = ref.ref
    group.ticket_url = ref.url
    session.flush()
    session.add(
        AuditEvent(
            actor_id=actor_id,
            action="ticket_created",
            target=f"finding_group:{group.id}",
            event_metadata={
                "integration_target_id": target.id,
                "kind": target.kind,
                "ref": ref.ref,
                "simulated": ref.simulated,
            },
        )
    )
    return target
