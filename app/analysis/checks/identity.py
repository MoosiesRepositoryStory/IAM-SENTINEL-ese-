"""Identity & hygiene checks (MFA, inactivity, console access, recent login)."""

from __future__ import annotations

from collections.abc import Iterable

from app.analysis.checks._util import make_finding
from app.analysis.registry import CheckContext, CheckMeta, register
from app.domain.enums import Category, Severity
from app.domain.records import Finding
from app.domain.timeutil import days_since


@register
class MfaDisabledCheck:
    meta = CheckMeta(
        id="iam.user.mfa_disabled",
        title="Console user without MFA",
        category=Category.IDENTITY,
        default_severity=Severity.HIGH,
        description="Human users with console access must have MFA enabled.",
        remediation="Enable a virtual or hardware MFA device for this user.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for p in ctx.dataset.principals:
            if p.kind != "user" or not p.console_access:
                continue
            if not p.mfa_enabled:
                yield make_finding(
                    self.meta.id,
                    title=f"{p.display_name} has console access but no MFA",
                    severity=self.meta.default_severity,
                    category=self.meta.category,
                    principal_uid=p.principal_uid,
                    recommendation=self.meta.remediation,
                    remediation_snippet=(
                        f"aws iam enable-mfa-device --user-name {p.username or p.display_name} ..."
                    ),
                    evidence={"console_access": True, "mfa_enabled": False},
                )


@register
class InactiveUserCheck:
    meta = CheckMeta(
        id="iam.user.inactive",
        title="Inactive user with active credentials",
        category=Category.HYGIENE,
        default_severity=Severity.MEDIUM,
        description="Users who have not logged in within the inactivity window "
        "but still hold active credentials should be disabled.",
        remediation="Disable or delete unused credentials.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        limit = ctx.thresholds.inactivity_days
        for p in ctx.dataset.principals:
            if not p.active or p.kind == "role":
                continue
            idle = days_since(p.last_login)
            if idle is not None and idle >= limit:
                yield make_finding(
                    self.meta.id,
                    title=f"{p.display_name} inactive for {idle} days",
                    severity=self.meta.default_severity,
                    category=self.meta.category,
                    principal_uid=p.principal_uid,
                    recommendation=self.meta.remediation,
                    evidence={"idle_days": idle, "threshold": limit},
                )


@register
class ServiceConsoleAccessCheck:
    meta = CheckMeta(
        id="iam.user.service_console_access",
        title="Service account with console access",
        category=Category.IDENTITY,
        default_severity=Severity.MEDIUM,
        description="Service/machine accounts should not have interactive console access.",
        remediation="Remove the login profile from this service account.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for p in ctx.dataset.principals:
            if p.is_service and p.console_access:
                yield make_finding(
                    self.meta.id,
                    title=f"Service account {p.display_name} has console access",
                    severity=self.meta.default_severity,
                    category=self.meta.category,
                    principal_uid=p.principal_uid,
                    recommendation=self.meta.remediation,
                    evidence={"account_type": p.account_type, "console_access": True},
                )


@register
class NoRecentLoginCheck:
    meta = CheckMeta(
        id="iam.user.no_recent_login",
        title="User has never logged in",
        category=Category.HYGIENE,
        default_severity=Severity.LOW,
        description="An active human user with no recorded login is likely dormant "
        "or a provisioning leftover.",
        remediation="Confirm the account is needed; otherwise remove it.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for p in ctx.dataset.principals:
            if p.kind != "user" or not p.active or p.is_service:
                continue
            if p.last_login is None:
                yield make_finding(
                    self.meta.id,
                    title=f"{p.display_name} has never logged in",
                    severity=self.meta.default_severity,
                    category=self.meta.category,
                    principal_uid=p.principal_uid,
                    recommendation=self.meta.remediation,
                    evidence={"last_login": None},
                )
