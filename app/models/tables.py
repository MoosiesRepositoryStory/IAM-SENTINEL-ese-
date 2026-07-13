"""ORM models mirroring the data model in §4.

Timestamps are stored as ISO-8601 UTC strings (spec: TEXT), keeping SQLite and
Postgres behavior identical. JSON columns use SQLAlchemy's portable ``JSON`` type.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, now_iso


class AppUser(Base, TimestampMixin):
    __tablename__ = "app_user"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, default="read_only")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_login_at: Mapped[str | None] = mapped_column(String, nullable=True)


class Account(Base, TimestampMixin):
    __tablename__ = "account"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    provider: Mapped[str] = mapped_column(String, nullable=False, default="aws")
    external_id: Mapped[str | None] = mapped_column(String, nullable=True)
    source_type: Mapped[str] = mapped_column(String, nullable=False)
    source_config: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("app_user.id"), nullable=True)

    runs: Mapped[list[Run]] = relationship(back_populates="account", cascade="all, delete-orphan")


class Run(Base, TimestampMixin):
    __tablename__ = "run"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("account.id"), nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="queued")
    trigger: Mapped[str] = mapped_column(String, nullable=False, default="manual")
    triggered_by: Mapped[int | None] = mapped_column(ForeignKey("app_user.id"), nullable=True)
    schedule_id: Mapped[int | None] = mapped_column(ForeignKey("schedule.id"), nullable=True)
    thresholds: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    started_at: Mapped[str | None] = mapped_column(String, nullable=True)
    finished_at: Mapped[str | None] = mapped_column(String, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress_pct: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    progress_stage: Mapped[str | None] = mapped_column(String, nullable=True)
    composite_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    report_path: Mapped[str | None] = mapped_column(String, nullable=True)

    account: Mapped[Account] = relationship(back_populates="runs")
    summary: Mapped[RunSummary | None] = relationship(
        back_populates="run", cascade="all, delete-orphan", uselist=False
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("ix_run_account", "account_id", "created_at"),)


class RunSummary(Base):
    __tablename__ = "run_summary"

    run_id: Mapped[int] = mapped_column(ForeignKey("run.id", ondelete="CASCADE"), primary_key=True)
    total_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    count_low: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    count_medium: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    count_high: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    count_critical: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    counts_by_category: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    counts_by_status: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    compliance_summary: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    new_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resolved_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    principals_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    principals_at_risk: Mapped[int | None] = mapped_column(Integer, nullable=True)

    run: Mapped[Run] = relationship(back_populates="summary")


class Principal(Base):
    __tablename__ = "principal"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("run.id", ondelete="CASCADE"), nullable=False)
    principal_uid: Mapped[str] = mapped_column(String, nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False, default="user")
    username: Mapped[str | None] = mapped_column(String, nullable=True)
    email: Mapped[str | None] = mapped_column(String, nullable=True)
    arn: Mapped[str | None] = mapped_column(String, nullable=True)
    role: Mapped[str | None] = mapped_column(String, nullable=True)
    account_type: Mapped[str | None] = mapped_column(String, nullable=True)
    active: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    console_access: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    mfa_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_login: Mapped[str | None] = mapped_column(String, nullable=True)
    password_last_changed: Mapped[str | None] = mapped_column(String, nullable=True)
    access_key_age_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attached_policy_ids: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    blast_radius_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reachable_actions: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reachable_sensitive: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_principal_run", "run_id"),
        Index("ix_principal_uid", "principal_uid"),
    )


class Policy(Base):
    __tablename__ = "policy"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("run.id", ondelete="CASCADE"), nullable=False)
    policy_uid: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    kind: Mapped[str | None] = mapped_column(String, nullable=True)
    document: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    statement_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    has_wildcard_action: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    has_wildcard_resource: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    uses_not_action: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    __table_args__ = (Index("ix_policy_run", "run_id"),)


class PermissionEdge(Base):
    __tablename__ = "permission_edge"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("run.id", ondelete="CASCADE"), nullable=False)
    src_type: Mapped[str] = mapped_column(String, nullable=False)
    src_uid: Mapped[str] = mapped_column(String, nullable=False)
    dst_type: Mapped[str] = mapped_column(String, nullable=False)
    dst_uid: Mapped[str] = mapped_column(String, nullable=False)
    relation: Mapped[str] = mapped_column(String, nullable=False)
    effect: Mapped[str | None] = mapped_column(String, nullable=True)
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    edge_metadata: Mapped[dict[str, Any] | None] = mapped_column("metadata", JSON, nullable=True)

    __table_args__ = (Index("ix_edge_run_src", "run_id", "src_uid"),)


class LogEvent(Base):
    __tablename__ = "log_event"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("run.id", ondelete="CASCADE"), nullable=False)
    ts: Mapped[str | None] = mapped_column(String, nullable=True)
    principal_uid: Mapped[str | None] = mapped_column(String, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    event_name: Mapped[str | None] = mapped_column(String, nullable=True)
    event_source: Mapped[str | None] = mapped_column(String, nullable=True)
    outcome: Mapped[str | None] = mapped_column(String, nullable=True)
    is_privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    is_sensitive_iam: Mapped[bool] = mapped_column(Boolean, default=False)
    raw: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    __table_args__ = (Index("ix_log_run_principal", "run_id", "principal_uid"),)


class FindingGroup(Base):
    __tablename__ = "finding_group"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("account.id"), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String, nullable=False)
    check_id: Mapped[str] = mapped_column(String, nullable=False)
    principal_uid: Mapped[str | None] = mapped_column(String, nullable=True)
    first_seen_run: Mapped[int | None] = mapped_column(ForeignKey("run.id"), nullable=True)
    last_seen_run: Mapped[int | None] = mapped_column(ForeignKey("run.id"), nullable=True)
    current_status: Mapped[str] = mapped_column(String, nullable=False, default="open")
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("app_user.id"), nullable=True)
    ticket_ref: Mapped[str | None] = mapped_column(String, nullable=True)

    __table_args__ = (
        UniqueConstraint("account_id", "fingerprint", name="uq_group_account_fingerprint"),
        Index("ix_group_fingerprint", "fingerprint"),
    )


class Finding(Base, TimestampMixin):
    __tablename__ = "finding"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("run.id", ondelete="CASCADE"), nullable=False)
    group_id: Mapped[int] = mapped_column(ForeignKey("finding_group.id"), nullable=False)
    check_id: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    category: Mapped[str] = mapped_column(String, nullable=False)
    principal_uid: Mapped[str | None] = mapped_column(String, nullable=True)
    resource: Mapped[str | None] = mapped_column(String, nullable=True)
    policy_uid: Mapped[str | None] = mapped_column(String, nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    likelihood: Mapped[int | None] = mapped_column(Integer, nullable=True)
    impact: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    remediation_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    compliance_tags: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String, nullable=False, default="open")

    run: Mapped[Run] = relationship(back_populates="findings")

    __table_args__ = (
        Index("ix_finding_run", "run_id", "severity"),
        Index("ix_finding_group", "group_id"),
    )


class FindingStatusHistory(Base, TimestampMixin):
    __tablename__ = "finding_status_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(
        ForeignKey("finding_group.id", ondelete="CASCADE"), nullable=False
    )
    from_status: Mapped[str | None] = mapped_column(String, nullable=True)
    to_status: Mapped[str] = mapped_column(String, nullable=False)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("app_user.id"), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)


class FindingComment(Base, TimestampMixin):
    __tablename__ = "finding_comment"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(
        ForeignKey("finding_group.id", ondelete="CASCADE"), nullable=False
    )
    author_id: Mapped[int] = mapped_column(ForeignKey("app_user.id"), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    edited_at: Mapped[str | None] = mapped_column(String, nullable=True)


class FindingException(Base, TimestampMixin):
    __tablename__ = "finding_exception"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(
        ForeignKey("finding_group.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[int] = mapped_column(ForeignKey("app_user.id"), nullable=False)
    expires_at: Mapped[str | None] = mapped_column(String, nullable=True)
    revoked_at: Mapped[str | None] = mapped_column(String, nullable=True)


class SavedView(Base, TimestampMixin):
    __tablename__ = "saved_view"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("app_user.id"), nullable=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    scope: Mapped[str] = mapped_column(String, nullable=False, default="private")
    config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)


class Schedule(Base, TimestampMixin):
    __tablename__ = "schedule"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[int] = mapped_column(
        ForeignKey("account.id", ondelete="CASCADE"), nullable=False
    )
    cron: Mapped[str] = mapped_column(String, nullable=False)
    thresholds: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("app_user.id"), nullable=True)
    last_run_at: Mapped[str | None] = mapped_column(String, nullable=True)
    next_run_at: Mapped[str | None] = mapped_column(String, nullable=True)


class AuditEvent(Base, TimestampMixin):
    __tablename__ = "audit_event"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("app_user.id"), nullable=True)
    action: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[str | None] = mapped_column(String, nullable=True)
    event_metadata: Mapped[dict[str, Any] | None] = mapped_column("metadata", JSON, nullable=True)
    ip: Mapped[str | None] = mapped_column(String, nullable=True)


__all__ = [
    "AppUser",
    "Account",
    "Run",
    "RunSummary",
    "Principal",
    "Policy",
    "PermissionEdge",
    "LogEvent",
    "FindingGroup",
    "Finding",
    "FindingStatusHistory",
    "FindingComment",
    "FindingException",
    "SavedView",
    "Schedule",
    "AuditEvent",
    "now_iso",
]
