"""Auth / CloudTrail log parser.

Two input shapes are supported, matching the original tool's contract:

1. **CloudTrail-style JSON** — one JSON object per line (``{...}``) with the usual
   ``eventTime`` / ``eventName`` / ``userIdentity`` / ``errorCode`` fields.
2. **Plaintext key=value** — a leading timestamp followed by ``key=value`` tokens,
   e.g. ``2026-06-01T12:03:44Z ConsoleLogin user=intern ip=203.0.113.5 result=failure``.

Design contract (see §12.1): the parser NEVER raises on a single line. It always
returns either a well-formed :class:`LogEventRecord` or ``None`` (a clean
"unparsed" marker), so a corrupt line can never break a scan.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from typing import Any

from app.domain.records import LogEventRecord
from app.domain.timeutil import parse_dt

# Key aliases accepted in the plaintext format -> canonical field.
_KEY_ALIASES: dict[str, str] = {
    "user": "principal",
    "username": "principal",
    "principal": "principal",
    "actor": "principal",
    "identity": "principal",
    "ip": "source_ip",
    "source_ip": "source_ip",
    "sourceip": "source_ip",
    "srcip": "source_ip",
    "addr": "source_ip",
    "event": "event_name",
    "event_name": "event_name",
    "action": "event_name",
    "source": "event_source",
    "event_source": "event_source",
    "outcome": "outcome",
    "result": "outcome",
    "status": "outcome",
}

# Matches ``key=value`` where value is bare or quoted.
_KV = re.compile(r'(?P<key>[A-Za-z_][\w.]*)=(?P<val>"[^"]*"|\'[^\']*\'|\S+)')
# Leading timestamp: ISO-8601 or ``[bracketed]`` or ``YYYY-MM-DD HH:MM:SS``.
_LEADING_TS = re.compile(
    r"^\s*[\[<]?\s*"
    r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s*[\]>]?"
)

_SENSITIVE_IAM_EVENTS: set[str] = {
    "CreateUser",
    "CreateAccessKey",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "PassRole",
    "UpdateAssumeRolePolicy",
    "DeleteUser",
    "CreateRole",
}
_PRIVILEGED_EVENTS: set[str] = _SENSITIVE_IAM_EVENTS | {"AssumeRole", "ConsoleLogin"}


def _normalize_outcome(value: str | None) -> str | None:
    if value is None:
        return None
    v = value.strip().strip("\"'").lower()
    if not v:
        return None
    if v in {"denied", "accessdenied", "access_denied", "deny", "403"}:
        return "denied"
    if v in {"failure", "failed", "fail", "error", "false", "401"}:
        return "failure"
    if v in {"success", "succeeded", "ok", "true", "200", "allow", "allowed"}:
        return "success"
    return v


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        return value[1:-1]
    return value


def parse_line(line: str) -> LogEventRecord | None:
    """Parse a single log line into a :class:`LogEventRecord` or ``None``.

    Guarantees: never raises; returns ``None`` for blank/comment/unparseable input.
    """
    if line is None:
        return None
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    try:
        stripped = text.lstrip()
        if stripped.startswith("{"):
            return _parse_json_line(stripped)
        return _parse_plaintext_line(text)
    except Exception:  # noqa: BLE001 — the parser must never crash a scan.
        return None


def _parse_json_line(text: str) -> LogEventRecord | None:
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    return _from_cloudtrail(obj)


def _from_cloudtrail(obj: dict[str, Any]) -> LogEventRecord:
    identity = obj.get("userIdentity") or {}
    if not isinstance(identity, dict):
        identity = {}
    principal_uid = (
        identity.get("userName")
        or identity.get("arn")
        or identity.get("principalId")
        or obj.get("principal")
        or obj.get("user")
    )

    event_name = obj.get("eventName") or obj.get("event")
    event_source = obj.get("eventSource") or obj.get("source")
    source_ip = obj.get("sourceIPAddress") or obj.get("ip")
    ts = parse_dt(obj.get("eventTime") or obj.get("ts") or obj.get("time"))

    # Outcome: CloudTrail encodes login result in responseElements and errors in
    # errorCode / errorMessage.
    outcome = None
    response = obj.get("responseElements") or {}
    if isinstance(response, dict) and "ConsoleLogin" in response:
        outcome = _normalize_outcome(str(response.get("ConsoleLogin")))
    if obj.get("errorCode"):
        code = str(obj["errorCode"])
        outcome = "denied" if "AccessDenied" in code or "Forbidden" in code else "failure"
    if outcome is None:
        raw_outcome = obj.get("outcome")
        outcome = (
            _normalize_outcome(str(raw_outcome) if raw_outcome is not None else None) or "success"
        )

    return _finalize(
        ts=ts,
        principal_uid=str(principal_uid) if principal_uid else None,
        source_ip=str(source_ip) if source_ip else None,
        event_name=str(event_name) if event_name else None,
        event_source=str(event_source) if event_source else None,
        outcome=outcome,
        raw=obj,
    )


def _parse_plaintext_line(text: str) -> LogEventRecord | None:
    fields: dict[str, str] = {}

    ts_match = _LEADING_TS.match(text)
    ts = parse_dt(ts_match.group("ts")) if ts_match else None
    remainder = text[ts_match.end() :] if ts_match else text

    for m in _KV.finditer(remainder):
        canonical = _KEY_ALIASES.get(m.group("key").lower())
        if canonical:
            fields[canonical] = _strip_quotes(m.group("val"))

    # A bare word before the first key=value is treated as the event name.
    if "event_name" not in fields:
        head = _KV.split(remainder)[0].strip()
        # head may still contain junk; take the first token that looks like an event
        tokens = [t for t in re.split(r"\s+", head) if t]
        for tok in tokens:
            if re.fullmatch(r"[A-Za-z][\w:.-]*", tok):
                fields["event_name"] = tok
                break

    if ts is None and not fields:
        return None

    return _finalize(
        ts=ts,
        principal_uid=fields.get("principal"),
        source_ip=fields.get("source_ip"),
        event_name=fields.get("event_name"),
        event_source=fields.get("event_source"),
        outcome=_normalize_outcome(fields.get("outcome")),
        raw={"line": text},
    )


def _finalize(
    *,
    ts: Any,
    principal_uid: str | None,
    source_ip: str | None,
    event_name: str | None,
    event_source: str | None,
    outcome: str | None,
    raw: dict[str, Any],
) -> LogEventRecord:
    bare_event = (event_name or "").split(":")[-1]
    is_sensitive_iam = (
        bool(event_source and "iam" in event_source.lower() and bare_event in _SENSITIVE_IAM_EVENTS)
        or bare_event in _SENSITIVE_IAM_EVENTS
    )
    is_privileged = bare_event in _PRIVILEGED_EVENTS
    return LogEventRecord(
        ts=ts,
        principal_uid=principal_uid,
        source_ip=source_ip,
        event_name=event_name,
        event_source=event_source,
        outcome=outcome,
        is_privileged=is_privileged,
        is_sensitive_iam=is_sensitive_iam,
        raw=raw,
    )


# CloudTrail event names that are authentication/sign-in events, not IAM policy
# actions — they must never appear in a granted-vs-used action diff (§6.3).
_NON_ACTION_EVENTS: set[str] = {"ConsoleLogin", "CheckMfa", "ExitRole", "RenewRole"}
# eventSource prefixes that don't correspond to an IAM action namespace.
_NON_ACTION_SERVICES: set[str] = {"signin", "console"}


def to_iam_action(event_source: str | None, event_name: str | None) -> str | None:
    """Best-effort map a CloudTrail ``(eventSource, eventName)`` to an IAM
    ``"service:Action"`` string, or ``None`` when the event isn't a policy
    action we can compare against grants.

    Returns ``None`` for sign-in events (``ConsoleLogin``) and for events we
    can't qualify to a service. The service prefix is taken from ``eventSource``
    (``s3.amazonaws.com`` -> ``s3``); this matches the IAM action namespace for
    the vast majority of services (and all of the simulated org's), with a
    documented handful of real-AWS exceptions (e.g. ``monitoring`` ->
    ``cloudwatch``) not modeled here since the mock never emits them.
    """
    if not event_name or event_name in _NON_ACTION_EVENTS:
        return None
    if ":" in event_name:
        # A plaintext log may already have written a qualified "service:Action".
        return event_name
    if not event_source:
        return None
    service = event_source.split(".")[0].strip().lower()
    if not service or service in _NON_ACTION_SERVICES:
        return None
    return f"{service}:{event_name}"


def parse_lines(lines: Iterable[str]) -> Iterator[LogEventRecord]:
    """Parse an iterable of lines, silently skipping unparseable ones."""
    for line in lines:
        record = parse_line(line)
        if record is not None:
            yield record


def parse_text(text: str) -> list[LogEventRecord]:
    """Parse a whole log blob into records."""
    return list(parse_lines(text.splitlines()))
