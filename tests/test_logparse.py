"""Log parser tests — table-driven, property-based, and adversarial (§12.1)."""

from __future__ import annotations

import pytest
from app.domain.logparse import parse_line, parse_text
from hypothesis import given
from hypothesis import strategies as st


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (
            "2026-06-01T08:20:41Z ConsoleLogin user=intern ip=203.0.113.9 result=failure",
            {
                "event_name": "ConsoleLogin",
                "principal_uid": "intern",
                "source_ip": "203.0.113.9",
                "outcome": "failure",
            },
        ),
        (
            "[2026-06-01 08:20:41] AssumeRole actor=ci-deploy srcip=10.0.0.1 status=success",
            {
                "event_name": "AssumeRole",
                "principal_uid": "ci-deploy",
                "source_ip": "10.0.0.1",
                "outcome": "success",
            },
        ),
        (
            '{"eventTime":"2026-06-05T09:30:12Z","eventName":"CreateUser",'
            '"eventSource":"iam.amazonaws.com","sourceIPAddress":"203.0.113.9",'
            '"userIdentity":{"userName":"intern"},"errorCode":"AccessDenied"}',
            {
                "event_name": "CreateUser",
                "principal_uid": "intern",
                "source_ip": "203.0.113.9",
                "outcome": "denied",
            },
        ),
    ],
)
def test_known_lines_parse_expected_fields(line: str, expected: dict) -> None:
    rec = parse_line(line)
    assert rec is not None
    for key, value in expected.items():
        assert getattr(rec, key) == value


def test_cloudtrail_flags_sensitive_iam() -> None:
    rec = parse_line(
        '{"eventName":"CreateUser","eventSource":"iam.amazonaws.com",'
        '"userIdentity":{"userName":"x"},"errorCode":"AccessDenied"}'
    )
    assert rec is not None
    assert rec.is_sensitive_iam is True
    assert rec.outcome == "denied"


def test_cloudtrail_record_with_no_outcome_field_defaults_to_success() -> None:
    """An ordinary CloudTrail API-call record (no ``errorCode``, no
    ``responseElements``) has no explicit outcome — that must resolve to
    ``"success"``, not the string ``"none"``. Regression test for a fallback
    bug: ``_normalize_outcome(str(obj.get("outcome")))`` stringified a
    missing key's ``None`` into the literal text ``"None"``, which normalized
    to the unrecognized-but-truthy string ``"none"`` and silently defeated the
    intended ``or "success"`` default."""
    rec = parse_line(
        '{"eventName":"GetObject","eventSource":"s3.amazonaws.com",'
        '"userIdentity":{"userName":"alice"}}'
    )
    assert rec is not None
    assert rec.outcome == "success"


@pytest.mark.parametrize(
    "line",
    ["", "   ", "# a comment", "not a real log line at all", "{ broken json", "\x00\x01garbage"],
)
def test_unparseable_lines_return_none_or_safe(line: str) -> None:
    # Must never raise; returns None or a record (never a crash).
    result = parse_line(line)
    assert result is None or result.event_name is None or isinstance(result.event_name, str)


def test_outcome_normalization_aliases() -> None:
    assert parse_line("2026-01-01T00:00:00Z Login result=FAILED").outcome == "failure"
    assert parse_line("2026-01-01T00:00:00Z Login result=denied").outcome == "denied"
    assert parse_line("2026-01-01T00:00:00Z Login result=200").outcome == "success"


def test_mixed_format_blob() -> None:
    blob = (
        "# header\n"
        "2026-06-01T00:00:00Z ConsoleLogin user=a ip=1.1.1.1 result=success\n"
        '{"eventName":"AssumeRole","userIdentity":{"userName":"b"}}\n'
        "\n"
        "garbage line with no fields ;;;\n"
    )
    records = parse_text(blob)
    assert len(records) >= 2
    assert {r.event_name for r in records} >= {"ConsoleLogin", "AssumeRole"}


# --- property-based ----------------------------------------------------------
@given(
    st.text(max_size=500),
)
def test_parser_never_raises_on_arbitrary_text(line: str) -> None:
    # The contract: no input line can ever crash the parser.
    result = parse_line(line)
    assert result is None or result is not None  # i.e. it returned


@given(
    principal=st.from_regex(r"[a-z][a-z0-9_-]{0,20}", fullmatch=True),
    ip=st.from_regex(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", fullmatch=True),
)
def test_roundtrip_plaintext_fields(principal: str, ip: str) -> None:
    line = f"2026-06-01T12:00:00Z ConsoleLogin user={principal} ip={ip} result=success"
    rec = parse_line(line)
    assert rec is not None
    assert rec.principal_uid == principal
    assert rec.source_ip == ip
    assert rec.outcome == "success"


def test_huge_line_is_handled() -> None:
    line = "2026-06-01T00:00:00Z Login " + "x=y " * 5000
    assert parse_line(line) is not None
