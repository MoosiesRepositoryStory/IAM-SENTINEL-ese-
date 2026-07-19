"""Privilege & escalation checks.

These are *structural* detections in Phase 0 (read directly off attached
policies and role trust documents). Phase 3 enriches them with the permission
graph so escalation findings can render the actual assume-role path.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.analysis import least_privilege
from app.analysis.checks._util import (
    action_matches,
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
            if not action_matches(actions, "iam:PassRole"):
                continue
            partners = sorted(a for a in _ESCALATION_PARTNERS if action_matches(actions, a))
            if partners:
                evidence: dict[str, object] = {
                    "escalation_path": [p.display_name, "iam:PassRole", *partners],
                    "partner_actions": partners,
                }
                # Real graph-derived path (§6.2), when the permission graph
                # traced this principal all the way to an admin-equivalent
                # node — e.g. "intern -> iam:CreateAccessKey -> bob (admin)".
                graph_paths = ctx.graph.escalations.get(p.principal_uid)
                if graph_paths:
                    evidence["graph_path"] = graph_paths[0].hops
                    evidence["graph_path_via"] = graph_paths[0].via
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
                    evidence=evidence,
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
                if not pol.is_assume_role_statement(st):
                    continue
                principal = st.get("Principal")
                if pol.principal_has_wildcard(principal):
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
            if not has_sensitive(granted) - {"*"}:
                continue
            # Only assess identities we could actually observe acting: ones
            # with a long-term credential (console or access key). A role with
            # no standing credential and no CloudTrail of its own can't be
            # honestly evaluated by an activity-based check — flagging its
            # grants as "unused" would just be a logging gap masquerading as a
            # finding. Its blast-radius/escalation findings still stand.
            if not (p.console_access or p.access_key_age_days is not None):
                continue

            rec = least_privilege.recommend(
                principal_uid=p.principal_uid,
                granted_actions=granted,
                policies=ctx.dataset.policies_for(p),
                used_actions=ctx.activity.used_by(p.principal_uid),
                event_count=ctx.activity.events_for(p.principal_uid),
                window_days=ctx.activity.window_days,
            )
            if not rec.exceeds_threshold:
                continue

            n = len(rec.unused_sensitive)
            title = (
                f"{p.display_name} has {n} unused sensitive grant(s)"
                if rec.confident
                else f"{p.display_name}: {n} sensitive grant(s) with no observed use"
            )
            evidence: dict[str, object] = {
                "unused_sensitive": rec.unused_sensitive,
                "used_actions": rec.used_actions,
                "window_days": rec.window_days,
                "events_observed": rec.event_count,
                "confidence": "confident" if rec.confident else "insufficient_data",
            }
            if rec.insufficient_reason:
                evidence["insufficient_reason"] = rec.insufficient_reason
            yield make_finding(
                self.meta.id,
                title=title,
                severity=self.meta.default_severity,
                category=self.meta.category,
                principal_uid=p.principal_uid,
                recommendation=rec.summary,
                remediation_snippet=rec.suggested_policy_json,
                evidence=evidence,
            )
