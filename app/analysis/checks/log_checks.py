"""Log-derived checks (brute force, privileged logins, denied sensitive IAM)."""

from __future__ import annotations

from collections.abc import Iterable

from app.analysis.checks._util import make_finding
from app.analysis.registry import CheckContext, CheckMeta, register
from app.domain.enums import Category, Severity
from app.domain.records import Finding


@register
class RepeatedLoginFailuresCheck:
    meta = CheckMeta(
        id="log.repeated_login_failures",
        title="Repeated login failures (possible brute force)",
        category=Category.LOG,
        default_severity=Severity.MEDIUM,
        description="A source produced more failed logins than the configured threshold.",
        remediation="Investigate the source IP; consider lockout / IP blocking.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        threshold = ctx.thresholds.failed_logins
        counts: dict[tuple[str | None, str | None], int] = {}
        for ev in ctx.dataset.log_events:
            if ev.event_name and ev.event_name.endswith("ConsoleLogin") and ev.outcome == "failure":
                key = (ev.principal_uid, ev.source_ip)
                counts[key] = counts.get(key, 0) + 1
        for (principal_uid, ip), count in counts.items():
            if count >= threshold:
                yield make_finding(
                    self.meta.id,
                    title=f"{count} failed logins for {principal_uid or 'unknown'} from {ip}",
                    severity=self.meta.default_severity,
                    category=self.meta.category,
                    principal_uid=principal_uid,
                    resource=ip,
                    recommendation=self.meta.remediation,
                    evidence={"failure_count": count, "source_ip": ip, "threshold": threshold},
                )


@register
class PrivilegedLoginCheck:
    meta = CheckMeta(
        id="log.privileged_login",
        title="Privileged principal console login",
        category=Category.LOG,
        default_severity=Severity.LOW,
        description="An administrator-equivalent principal logged in to the console; "
        "worth surfacing for awareness.",
        remediation="Confirm the login was expected; prefer federated/temporary access.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        # Determine which principals are privileged from the dataset.
        from app.analysis.checks._util import grants_admin, principal_granted_actions

        privileged = {
            p.principal_uid
            for p in ctx.dataset.principals
            if grants_admin(principal_granted_actions(ctx, p))
        }
        seen: set[str] = set()
        for ev in ctx.dataset.log_events:
            if not ev.event_name or not ev.event_name.endswith("ConsoleLogin"):
                continue
            if ev.outcome and ev.outcome != "success":
                continue
            uid = ev.principal_uid
            if uid and uid in privileged and uid not in seen:
                seen.add(uid)
                yield make_finding(
                    self.meta.id,
                    title=f"Privileged user {uid} logged in to console",
                    severity=self.meta.default_severity,
                    category=self.meta.category,
                    principal_uid=uid,
                    recommendation=self.meta.remediation,
                    evidence={"source_ip": ev.source_ip, "ts": str(ev.ts)},
                )


@register
class ServiceInteractiveLoginCheck:
    meta = CheckMeta(
        id="log.service_interactive_login",
        title="Service account interactive login",
        category=Category.LOG,
        default_severity=Severity.HIGH,
        description="A service/machine account performed an interactive console login, "
        "which usually indicates credential misuse.",
        remediation="Rotate the service credential and investigate the login.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        service_uids = {p.principal_uid for p in ctx.dataset.principals if p.is_service}
        seen: set[str] = set()
        for ev in ctx.dataset.log_events:
            if not ev.event_name or not ev.event_name.endswith("ConsoleLogin"):
                continue
            uid = ev.principal_uid
            if uid and uid in service_uids and uid not in seen:
                seen.add(uid)
                yield make_finding(
                    self.meta.id,
                    title=f"Service account {uid} performed interactive login",
                    severity=self.meta.default_severity,
                    category=self.meta.category,
                    principal_uid=uid,
                    recommendation=self.meta.remediation,
                    evidence={"source_ip": ev.source_ip, "ts": str(ev.ts)},
                )


@register
class DeniedSensitiveIamCheck:
    meta = CheckMeta(
        id="log.denied_sensitive_iam",
        title="Denied sensitive IAM action",
        category=Category.LOG,
        default_severity=Severity.MEDIUM,
        description="A sensitive IAM action was attempted and denied — a signal of "
        "reconnaissance or a misconfigured automation.",
        remediation="Investigate the principal and the denied action.",
    )

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        for ev in ctx.dataset.log_events:
            if ev.is_sensitive_iam and ev.outcome == "denied":
                yield make_finding(
                    self.meta.id,
                    title=f"Denied {ev.event_name} by {ev.principal_uid or 'unknown'}",
                    severity=self.meta.default_severity,
                    category=self.meta.category,
                    principal_uid=ev.principal_uid,
                    resource=ev.event_name,
                    recommendation=self.meta.remediation,
                    evidence={
                        "event_name": ev.event_name,
                        "source_ip": ev.source_ip,
                        "ts": str(ev.ts),
                    },
                )
