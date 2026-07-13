"""Shared helpers for checks."""

from __future__ import annotations

from app.analysis.registry import CheckContext
from app.compliance.mappings import compliance_tags_for
from app.domain import policy as pol
from app.domain.records import Finding, PrincipalRecord


def principal_granted_actions(ctx: CheckContext, principal: PrincipalRecord) -> set[str]:
    """Union of actions granted to a principal across its attached policies."""
    actions: set[str] = set()
    for policy in ctx.dataset.policies_for(principal):
        actions |= policy.granted_actions
    return actions


def grants_admin(actions: set[str]) -> bool:
    """A principal is admin-equivalent if it can perform any action (``*``)."""
    return "*" in actions


def has_sensitive(actions: set[str]) -> set[str]:
    """Subset of ``actions`` that are in the sensitive catalog (wildcard-aware)."""
    return {a for a in actions if pol.is_sensitive_action(a, pol.SENSITIVE_ACTIONS)}


def make_finding(check_id: str, **kwargs: object) -> Finding:
    """Build a :class:`Finding`, auto-attaching compliance tags for the check."""
    kwargs.setdefault("compliance_tags", compliance_tags_for(check_id))
    return Finding(check_id=check_id, **kwargs)  # type: ignore[arg-type]
