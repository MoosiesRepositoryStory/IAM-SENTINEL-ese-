"""Privilege & escalation checks.

These are *structural* detections in Phase 0 (read directly off attached
policies and role trust documents). Phase 3 enriches them with the permission
graph so escalation findings can render the actual assume-role path.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.analysis.checks._util import (
    grants_admin,
    has_sensitive,
    make_finding,
    principal_granted_actions,
)
from app.analysis.registry import CheckContext, CheckMeta, register
from app.domain import policy as pol
from app.domain.enums import Category, Severity
from app.domain.records import Finding

# Actions that, combined with iam:PassRole, enable privilege escalation.
_ESCALATION_PARTNERS = {
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "ec2:RunInstances",
    "lambda:CreateFunction",
}


def _matches(actions: set[str], target: str) -> bool:
    """Whether ``actions`` grants ``target`` (respecting ``*`` / ``service:*``)."""
    if "*" in actions or target in actions:
        return True
    service = target.split(":")[0]
    return f"{service}:*" in actions


@register
class AdminAccessCheck:
    meta = CheckMeta(
        id="iam.principal.admin_access",
        title="Principal has administrator-equivalent access",
        category=Category.PRIVILEGE,
        default_severity=Severity.HIGH,
        description="A principal can perform any action (Action '*'), i.e. full admin.",
        remediation="Replace broad admin access with scoped, task-specific policies.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for p in ctx.dataset.principals:
            actions = principal_granted_actions(ctx, p)
            if grants_admin(actions):
                yield make_finding(
                    self.meta.id,
                    title=f"{p.display_name} has administrator-equivalent access",
                    severity=self.meta.default_severity,
                    category=self.meta.category,
                    principal_uid=p.principal_uid,
                    recommendation=self.meta.remediation,
                    evidence={"granted": "*", "policies": p.attached_policy_uids},
                )


@register
class PassRoleEscalationCheck:
    meta = CheckMeta(
        id="iam.escalation.passrole_createkey",
        title="Privilege escalation via iam:PassRole",
        category=Category.PRIVILEGE,
        default_severity=Severity.CRITICAL,
        description="A principal holds iam:PassRole together with an action that can "
        "attach that role to a resource it controls, enabling privilege escalation.",
        remediation="Remove iam:PassRole or scope it to non-privileged roles only.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for p in ctx.dataset.principals:
            actions = principal_granted_actions(ctx, p)
            if not _matches(actions, "iam:PassRole"):
                continue
            partners = sorted(a for a in _ESCALATION_PARTNERS if _matches(actions, a))
            if partners:
                yield make_finding(
                    self.meta.id,
                    title=f"{p.display_name} can escalate privileges via iam:PassRole",
                    severity=self.meta.default_severity,
                    category=self.meta.category,
                    principal_uid=p.principal_uid,
                    recommendation=self.meta.remediation,
                    remediation_snippet=(
                        '{"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"}'
                    ),
                    evidence={
                        "escalation_path": [p.display_name, "iam:PassRole", *partners],
                        "partner_actions": partners,
                    },
                )


@register
class TrustWildcardPrincipalCheck:
    meta = CheckMeta(
        id="iam.role.trust_wildcard_principal",
        title="Role trust policy allows any principal",
        category=Category.PRIVILEGE,
        default_severity=Severity.CRITICAL,
        description="A role's trust policy sets Principal '*', so anyone (including "
        "external accounts) can assume it.",
        remediation="Restrict the trust policy Principal to specific accounts/roles.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for p in ctx.dataset.principals:
            if p.kind != "role":
                continue
            trust = p.raw.get("trust_policy") or p.raw.get("AssumeRolePolicyDocument")
            if not isinstance(trust, dict):
                continue
            for st in pol.statements(trust):
                principal = st.get("Principal")
                if principal == "*" or (isinstance(principal, dict) and "*" in principal.values()):
                    yield make_finding(
                        self.meta.id,
                        title=f"Role {p.display_name} can be assumed by any principal",
                        severity=self.meta.default_severity,
                        category=self.meta.category,
                        principal_uid=p.principal_uid,
                        recommendation=self.meta.remediation,
                        evidence={"trust_statement": st},
                    )
                    break


@register
class UnusedGrantsCheck:
    meta = CheckMeta(
        id="iam.least_privilege.unused_grants",
        title="Sensitive grants never exercised",
        category=Category.PRIVILEGE,
        default_severity=Severity.MEDIUM,
        description="A principal is granted sensitive actions it never used in the "
        "observed activity window (least-privilege violation).",
        remediation="Remove the unused grants; attach the suggested least-privilege policy.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        if ctx.activity.window_days <= 0:
            return
        for p in ctx.dataset.principals:
            granted = principal_granted_actions(ctx, p)
            sensitive_granted = has_sensitive(granted) - {"*"}
            if not sensitive_granted:
                continue
            used = ctx.activity.used_by(p.principal_uid)
            unused = {a for a in sensitive_granted if a not in used}
            if unused and len(unused) / max(len(sensitive_granted), 1) >= 0.6:
                yield make_finding(
                    self.meta.id,
                    title=f"{p.display_name} never used {len(unused)} sensitive grants",
                    severity=self.meta.default_severity,
                    category=self.meta.category,
                    principal_uid=p.principal_uid,
                    recommendation=self.meta.remediation,
                    evidence={
                        "unused_sensitive": sorted(unused),
                        "window_days": ctx.activity.window_days,
                    },
                )
