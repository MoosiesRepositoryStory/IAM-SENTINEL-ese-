"""Inventory checks (orphaned principals)."""

from __future__ import annotations

from collections.abc import Iterable

from app.analysis.checks._util import make_finding
from app.analysis.registry import CheckContext, CheckMeta, register
from app.domain.enums import Category, Severity
from app.domain.records import Finding


@register
class OrphanedPrincipalCheck:
    meta = CheckMeta(
        id="inventory.orphaned_principal",
        title="Orphaned principal with no policies",
        category=Category.INVENTORY,
        default_severity=Severity.LOW,
        description="A principal has no attached policies and no observed activity — "
        "likely an orphaned or forgotten identity.",
        remediation="Confirm the identity is needed; otherwise remove it.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for p in ctx.dataset.principals:
            if p.attached_policy_uids:
                continue
            # is_active covers login-only identities too (see credential.py):
            # a principal that logged in but has no policy actions is not
            # "orphaned," it's just unprivileged.
            if ctx.activity.is_active(p.principal_uid):
                continue
            yield make_finding(
                self.meta.id,
                title=f"{p.display_name} has no policies attached",
                severity=self.meta.default_severity,
                category=self.meta.category,
                principal_uid=p.principal_uid,
                recommendation=self.meta.remediation,
                evidence={"attached_policies": 0},
            )
