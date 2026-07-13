"""Policy-shape checks (wildcards, sensitive-on-star, NotAction, broad resource)."""

from __future__ import annotations

import json
from collections.abc import Iterable

from app.analysis.checks._util import has_sensitive, make_finding
from app.analysis.registry import CheckContext, CheckMeta, register
from app.domain import policy as pol
from app.domain.enums import Category, Severity
from app.domain.records import Finding


@register
class WildcardActionCheck:
    meta = CheckMeta(
        id="policy.wildcard_action",
        title="Policy grants wildcard action",
        category=Category.POLICY,
        default_severity=Severity.HIGH,
        description="A policy statement allows Action '*', granting far more than needed.",
        remediation="Replace '*' with the specific actions the workload requires.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for policy in ctx.dataset.policies:
            if policy.has_wildcard_action:
                yield make_finding(
                    self.meta.id,
                    title=f"Policy '{policy.name}' allows Action '*'",
                    severity=self.meta.default_severity,
                    category=self.meta.category,
                    policy_uid=policy.policy_uid,
                    recommendation=self.meta.remediation,
                    evidence={"statements": pol.statements(policy.document)},
                )


@register
class SensitiveActionOnStarCheck:
    meta = CheckMeta(
        id="policy.sensitive_action_on_star",
        title="Sensitive action on all resources",
        category=Category.PRIVILEGE,
        default_severity=Severity.HIGH,
        description="A sensitive action (IAM/KMS/STS/...) is granted on Resource '*'.",
        remediation="Scope sensitive actions to specific resource ARNs.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for policy in ctx.dataset.policies:
            for st in pol.statements(policy.document):
                if not pol.is_allow(st):
                    continue
                if "*" not in pol.resources(st):
                    continue
                sensitive = has_sensitive(set(pol.actions(st)))
                if sensitive:
                    yield make_finding(
                        self.meta.id,
                        title=f"Policy '{policy.name}' grants sensitive actions on '*'",
                        severity=self.meta.default_severity,
                        category=self.meta.category,
                        policy_uid=policy.policy_uid,
                        recommendation=self.meta.remediation,
                        evidence={
                            "sensitive_actions": sorted(sensitive),
                            "statement": st,
                        },
                    )
                    break  # one finding per policy is enough


@register
class RiskyNotActionCheck:
    meta = CheckMeta(
        id="policy.risky_not_action",
        title="Allow statement uses NotAction",
        category=Category.POLICY,
        default_severity=Severity.MEDIUM,
        description="Allow + NotAction grants everything except a deny-list, which is "
        "almost always broader than intended.",
        remediation="Rewrite the statement as an explicit Action allow-list.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for policy in ctx.dataset.policies:
            for st in pol.statements(policy.document):
                if pol.is_allow(st) and pol.not_actions(st):
                    yield make_finding(
                        self.meta.id,
                        title=f"Policy '{policy.name}' uses Allow + NotAction",
                        severity=self.meta.default_severity,
                        category=self.meta.category,
                        policy_uid=policy.policy_uid,
                        recommendation=self.meta.remediation,
                        evidence={"not_action": pol.not_actions(st), "statement": st},
                    )
                    break


@register
class OverlyBroadResourceCheck:
    meta = CheckMeta(
        id="policy.overly_broad_resource",
        title="Non-sensitive policy scoped to all resources",
        category=Category.POLICY,
        default_severity=Severity.MEDIUM,
        description="A policy grants concrete actions but on Resource '*'; scope it down.",
        remediation="Restrict the Resource element to specific ARNs.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for policy in ctx.dataset.policies:
            # Skip policies already flagged by the wildcard/sensitive checks.
            if policy.has_wildcard_action:
                continue
            for st in pol.statements(policy.document):
                if not pol.is_allow(st):
                    continue
                actions = set(pol.actions(st))
                if not actions or has_sensitive(actions):
                    continue
                if "*" in pol.resources(st):
                    yield make_finding(
                        self.meta.id,
                        title=f"Policy '{policy.name}' allows actions on Resource '*'",
                        severity=self.meta.default_severity,
                        category=self.meta.category,
                        policy_uid=policy.policy_uid,
                        recommendation=self.meta.remediation,
                        remediation_snippet=json.dumps(
                            {"Resource": ["arn:aws:...:specific-resource"]}, indent=2
                        ),
                        evidence={"actions": sorted(actions), "statement": st},
                    )
                    break
