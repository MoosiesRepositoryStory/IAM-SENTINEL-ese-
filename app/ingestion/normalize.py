"""Turn a source-shaped :class:`RawDataset` into a canonical NormalizedDataset."""

from __future__ import annotations

from typing import Any

from app.domain import logparse
from app.domain.records import (
    LogEventRecord,
    NormalizedDataset,
    PolicyRecord,
    PrincipalRecord,
)
from app.domain.timeutil import parse_dt
from app.ingestion.base import RawDataset


def _principal(data: dict[str, Any]) -> PrincipalRecord:
    return PrincipalRecord(
        principal_uid=data["principal_uid"],
        kind=data.get("kind", "user"),
        username=data.get("username"),
        email=data.get("email"),
        arn=data.get("arn"),
        role=data.get("role"),
        account_type=data.get("account_type"),
        active=bool(data.get("active", True)),
        console_access=bool(data.get("console_access", False)),
        mfa_enabled=bool(data.get("mfa_enabled", False)),
        last_login=parse_dt(data.get("last_login")),
        password_last_changed=parse_dt(data.get("password_last_changed")),
        access_key_age_days=data.get("access_key_age_days"),
        attached_policy_uids=list(data.get("attached_policy_uids", [])),
        raw=data.get("raw", {}),
    )


def _policy(data: dict[str, Any]) -> PolicyRecord:
    return PolicyRecord(
        policy_uid=data["policy_uid"],
        name=data.get("name", data["policy_uid"]),
        document=data.get("document") or {},
        kind=data.get("kind"),
    )


def _log_event(data: dict[str, Any]) -> LogEventRecord | None:
    # Two shapes: a raw {"line": "..."} to parse, or pre-normalized fields.
    if set(data.keys()) == {"line"} or ("line" in data and "event_name" not in data):
        return logparse.parse_line(str(data["line"]))
    return LogEventRecord(
        ts=parse_dt(data.get("ts")),
        principal_uid=data.get("principal_uid"),
        source_ip=data.get("source_ip"),
        event_name=data.get("event_name"),
        event_source=data.get("event_source"),
        outcome=data.get("outcome"),
        is_privileged=bool(data.get("is_privileged", False)),
        is_sensitive_iam=bool(data.get("is_sensitive_iam", False)),
        raw=data.get("raw", data),
    )


def normalize(raw: RawDataset) -> NormalizedDataset:
    principals = [_principal(p) for p in raw.principals]
    policies = [_policy(p) for p in raw.policies]

    # Wire attachments both directions.
    attached_to: dict[str, list[str]] = {}
    for principal_uid, policy_uid in raw.attachments:
        attached_to.setdefault(policy_uid, []).append(principal_uid)
    for policy in policies:
        policy.attached_to = attached_to.get(policy.policy_uid, [])

    log_events = [ev for ev in (_log_event(e) for e in raw.log_events) if ev is not None]
    _reconcile_log_principals(principals, log_events)

    return NormalizedDataset(principals=principals, policies=policies, log_events=log_events)


def _reconcile_log_principals(
    principals: list[PrincipalRecord], log_events: list[LogEventRecord]
) -> None:
    """Rewrite log ``principal_uid`` values to canonical principal UIDs.

    Logs commonly identify actors by bare username or ARN, while inventory keys
    principals by ``principal_uid`` (e.g. ``user/bob``). Without this join,
    log-derived checks (privileged/service login) would silently never match.
    """
    alias: dict[str, str] = {}
    for p in principals:
        alias[p.principal_uid] = p.principal_uid
        if p.username:
            alias.setdefault(p.username, p.principal_uid)
        if p.arn:
            alias.setdefault(p.arn, p.principal_uid)
    for ev in log_events:
        if ev.principal_uid and ev.principal_uid in alias:
            ev.principal_uid = alias[ev.principal_uid]
