"""Integration-target admin CRUD (§7.5 / §10.4, Phase 4 Slice 5) — the
configured webhook/Jira/Slack destinations "Create ticket" picks from.

Gating is entirely route-level (``require_role(Capability.MANAGE_INTEGRATIONS)``
in ``app.web.settings_views``), same posture ``user_service`` documents for
``MANAGE_USERS``: this capability carries no internal role split, so there's
nothing here that needs its own ``actor_role`` re-check on top of the route
decorator.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.integrations.registry import KINDS
from app.models import AuditEvent, IntegrationTarget


class IntegrationError(ValueError):
    """Bad input: unknown kind, empty name, or a kind-specific required
    config field missing (e.g. webhook needs a URL)."""


# The one field each kind can't function without — checked at creation time
# so a target never sits in the picker silently unusable. Kept here (not in
# app.integrations) since it's about *admin input validation*, not adapter
# behavior — an adapter given a config missing this key would still degrade
# sensibly (see each adapter's own fallback), this is just a friendlier
# earlier error for the person setting the target up.
_REQUIRED_CONFIG_KEY = {"webhook": "url"}


def list_targets(session: Session) -> list[IntegrationTarget]:
    return list(session.scalars(select(IntegrationTarget).order_by(IntegrationTarget.created_at)))


def list_enabled_targets(session: Session) -> list[IntegrationTarget]:
    """The "Create ticket" target picker's source list."""
    return list(
        session.scalars(
            select(IntegrationTarget)
            .where(IntegrationTarget.enabled.is_(True))
            .order_by(IntegrationTarget.name)
        )
    )


def create_target(
    session: Session,
    *,
    kind: str,
    name: str,
    config: dict,
    actor_id: int | None = None,
) -> IntegrationTarget:
    name = (name or "").strip()
    if not name:
        raise IntegrationError("Name is required.")
    if kind not in KINDS:
        raise IntegrationError(f"Unknown integration kind: {kind!r}")
    required = _REQUIRED_CONFIG_KEY.get(kind)
    if required and not (config.get(required) or "").strip():
        raise IntegrationError(f"{kind} targets require a {required!r} value.")
    target = IntegrationTarget(
        kind=kind, name=name, config=config, enabled=True, created_by=actor_id
    )
    session.add(target)
    session.flush()
    session.add(
        AuditEvent(
            actor_id=actor_id,
            action="integration_created",
            target=f"integration_target:{target.id}",
            event_metadata={"kind": kind, "name": name},
        )
    )
    return target


def set_enabled(
    session: Session, target_id: int, enabled: bool, *, actor_id: int | None = None
) -> IntegrationTarget:
    target = session.get(IntegrationTarget, target_id)
    if target is None:
        raise IntegrationError("Integration target not found.")
    target.enabled = enabled
    session.flush()
    session.add(
        AuditEvent(
            actor_id=actor_id,
            action="integration_enabled" if enabled else "integration_disabled",
            target=f"integration_target:{target.id}",
        )
    )
    return target


def delete_target(session: Session, target_id: int, *, actor_id: int | None = None) -> None:
    target = session.get(IntegrationTarget, target_id)
    if target is None:
        raise IntegrationError("Integration target not found.")
    session.add(
        AuditEvent(
            actor_id=actor_id,
            action="integration_deleted",
            target=f"integration_target:{target.id}",
            event_metadata={"kind": target.kind, "name": target.name},
        )
    )
    session.delete(target)
    session.flush()
