"""Credential-hygiene checks (key age, password age, unused active creds)."""

from __future__ import annotations

from collections.abc import Iterable

from app.analysis.checks._util import make_finding
from app.analysis.registry import CheckContext, CheckMeta, register
from app.domain.enums import Category, Severity
from app.domain.records import Finding
from app.domain.timeutil import days_since


@register
class OldAccessKeyCheck:
    meta = CheckMeta(
        id="iam.credential.old_access_key",
        title="Access key older than rotation window",
        category=Category.CREDENTIAL,
        default_severity=Severity.HIGH,
        description="Access keys should be rotated within the configured window.",
        remediation="Rotate the access key and delete the old one.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        limit = ctx.thresholds.key_age_days
        for p in ctx.dataset.principals:
            age = p.access_key_age_days
            if age is not None and age >= limit:
                yield make_finding(
                    self.meta.id,
                    title=f"{p.display_name} access key is {age} days old",
                    severity=self.meta.default_severity,
                    category=self.meta.category,
                    principal_uid=p.principal_uid,
                    recommendation=self.meta.remediation,
                    remediation_snippet=(
                        f"aws iam create-access-key --user-name {p.username or p.display_name} "
                        "&& aws iam delete-access-key --access-key-id <OLD>"
                    ),
                    evidence={"key_age_days": age, "threshold": limit},
                )


@register
class StalePasswordCheck:
    meta = CheckMeta(
        id="iam.credential.stale_password",
        title="Password older than max age",
        category=Category.CREDENTIAL,
        default_severity=Severity.MEDIUM,
        description="Console passwords should be changed within the max-age window.",
        remediation="Require a password reset for this user.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        limit = ctx.thresholds.password_age_days
        for p in ctx.dataset.principals:
            if not p.console_access:
                continue
            age = days_since(p.password_last_changed)
            if age is not None and age >= limit:
                yield make_finding(
                    self.meta.id,
                    title=f"{p.display_name} password is {age} days old",
                    severity=self.meta.default_severity,
                    category=self.meta.category,
                    principal_uid=p.principal_uid,
                    recommendation=self.meta.remediation,
                    evidence={"password_age_days": age, "threshold": limit},
                )


@register
class UnusedActiveCredentialCheck:
    meta = CheckMeta(
        id="iam.credential.unused_active",
        title="Active credential with no recent activity",
        category=Category.CREDENTIAL,
        default_severity=Severity.MEDIUM,
        description="An active credential (console or access key) with zero activity "
        "in the observed log window is an unnecessary attack surface.",
        remediation="Disable the unused credential.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        # Only meaningful when we actually observed some activity window.
        if ctx.activity.window_days <= 0:
            return
        for p in ctx.dataset.principals:
            if not p.active:
                continue
            has_credential = p.console_access or p.access_key_age_days is not None
            if not has_credential:
                continue
            if not ctx.activity.used_by(p.principal_uid):
                yield make_finding(
                    self.meta.id,
                    title=f"{p.display_name} credential unused in last "
                    f"{ctx.activity.window_days} days",
                    severity=self.meta.default_severity,
                    category=self.meta.category,
                    principal_uid=p.principal_uid,
                    recommendation=self.meta.remediation,
                    evidence={"window_days": ctx.activity.window_days, "used_actions": 0},
                )
