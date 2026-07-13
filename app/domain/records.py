"""In-memory records the analysis engine operates on.

These mirror the persisted tables (§4) but are plain dataclasses so checks never
touch the ORM. The ingestion layer produces a :class:`NormalizedDataset`; the
engine consumes it and emits :class:`Finding` objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.domain import policy as pol
from app.domain.enums import Category, Severity


@dataclass(frozen=True)
class Thresholds:
    """Tunable knobs shared by threshold-based checks (editable in the UI)."""

    inactivity_days: int = 90
    password_age_days: int = 90
    key_age_days: int = 90
    failed_logins: int = 5

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Thresholds:
        data = data or {}
        base = cls()
        return cls(
            inactivity_days=int(data.get("inactivity_days", base.inactivity_days)),
            password_age_days=int(data.get("password_age_days", base.password_age_days)),
            key_age_days=int(data.get("key_age_days", base.key_age_days)),
            failed_logins=int(data.get("failed_logins", base.failed_logins)),
        )

    def to_dict(self) -> dict[str, int]:
        return {
            "inactivity_days": self.inactivity_days,
            "password_age_days": self.password_age_days,
            "key_age_days": self.key_age_days,
            "failed_logins": self.failed_logins,
        }


@dataclass
class PrincipalRecord:
    principal_uid: str
    kind: str = "user"  # user | role | service_account
    username: str | None = None
    email: str | None = None
    arn: str | None = None
    role: str | None = None  # business-role label
    account_type: str | None = None  # human | service | machine
    active: bool = True
    console_access: bool = False
    mfa_enabled: bool = False
    last_login: datetime | None = None
    password_last_changed: datetime | None = None
    access_key_age_days: int | None = None
    attached_policy_uids: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    # Computed during graph/blast-radius analysis (Phase 3); default 0 for now.
    blast_radius_score: int = 0
    reachable_actions: int = 0
    reachable_sensitive: int = 0

    @property
    def display_name(self) -> str:
        return self.username or self.arn or self.principal_uid

    @property
    def is_service(self) -> bool:
        return self.account_type == "service" or self.kind == "service_account"


@dataclass
class PolicyRecord:
    policy_uid: str
    name: str
    document: dict[str, Any] = field(default_factory=dict)
    kind: str | None = None  # managed | inline | aws_managed
    attached_to: list[str] = field(default_factory=list)  # principal_uids

    @property
    def statement_count(self) -> int:
        return len(pol.statements(self.document))

    @property
    def has_wildcard_action(self) -> bool:
        return pol.has_wildcard_action(self.document)

    @property
    def has_wildcard_resource(self) -> bool:
        return pol.has_wildcard_resource(self.document)

    @property
    def uses_not_action(self) -> bool:
        return pol.uses_not_action(self.document)

    @property
    def granted_actions(self) -> set[str]:
        return pol.granted_actions(self.document)


@dataclass
class LogEventRecord:
    ts: datetime | None = None
    principal_uid: str | None = None
    source_ip: str | None = None
    event_name: str | None = None
    event_source: str | None = None
    outcome: str | None = None  # success | failure | denied
    is_privileged: bool = False
    is_sensitive_iam: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """A single detected issue emitted by a check (pre-persistence).

    ``risk_score`` / ``likelihood`` / ``impact`` are populated by the risk scorer
    after the check runs; checks leave them at their defaults.
    """

    check_id: str
    title: str
    severity: Severity
    category: Category
    recommendation: str
    principal_uid: str | None = None
    resource: str | None = None
    policy_uid: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation_snippet: str | None = None
    compliance_tags: list[str] = field(default_factory=list)

    risk_score: int = 0
    likelihood: int = 3
    impact: int = 3


@dataclass
class NormalizedDataset:
    """Canonical, source-agnostic dataset the engine analyzes."""

    principals: list[PrincipalRecord] = field(default_factory=list)
    policies: list[PolicyRecord] = field(default_factory=list)
    log_events: list[LogEventRecord] = field(default_factory=list)

    # --- lazily-built indexes -------------------------------------------------
    def policy_by_uid(self) -> dict[str, PolicyRecord]:
        return {p.policy_uid: p for p in self.policies}

    def principal_by_uid(self) -> dict[str, PrincipalRecord]:
        return {p.principal_uid: p for p in self.principals}

    def policies_for(self, principal: PrincipalRecord) -> list[PolicyRecord]:
        index = self.policy_by_uid()
        return [index[uid] for uid in principal.attached_policy_uids if uid in index]

    def events_by_principal(self) -> dict[str, list[LogEventRecord]]:
        out: dict[str, list[LogEventRecord]] = {}
        for ev in self.log_events:
            if ev.principal_uid:
                out.setdefault(ev.principal_uid, []).append(ev)
        return out
