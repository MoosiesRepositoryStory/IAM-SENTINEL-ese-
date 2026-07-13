"""Fingerprint stability tests (§4.5, §12.1)."""

from __future__ import annotations

from app.domain.fingerprint import fingerprint


def test_same_logical_issue_same_fingerprint() -> None:
    a = fingerprint("iam.user.mfa_disabled", "user/intern")
    b = fingerprint("iam.user.mfa_disabled", "user/intern")
    assert a == b


def test_different_principal_differs() -> None:
    a = fingerprint("iam.user.mfa_disabled", "user/intern")
    b = fingerprint("iam.user.mfa_disabled", "user/alice")
    assert a != b


def test_different_resource_differs() -> None:
    a = fingerprint("policy.wildcard_action", None, "res-a", "pol")
    b = fingerprint("policy.wildcard_action", None, "res-b", "pol")
    assert a != b


def test_none_and_empty_are_equivalent() -> None:
    assert fingerprint("c", None, None, None) == fingerprint("c", "", "", "")


def test_is_hex_sha256() -> None:
    fp = fingerprint("c", "p")
    assert len(fp) == 64
    int(fp, 16)  # parses as hex -> no exception
