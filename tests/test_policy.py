"""Direct unit tests for app.domain.policy's structural statement readers."""

from __future__ import annotations

from app.domain import policy as pol

# --- resources() / NotResource -----------------------------------------------


def test_resources_returns_the_resource_list() -> None:
    st = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": ["arn:aws:s3:::b"]}
    assert pol.resources(st) == ["arn:aws:s3:::b"]


def test_resources_with_not_resource_is_treated_as_unbounded() -> None:
    """A NotResource statement applies to every resource except the ones
    listed — the complement, not the list itself. Returning the excluded
    list as if it were the granted set would be a semantic inversion; this
    structural reader instead treats it as unbounded ("*"), the same
    approximation already used for NotAction in granted_actions()."""
    st = {"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::secret"}
    assert pol.resources(st) == ["*"]


def test_resources_with_not_resource_list_is_treated_as_unbounded() -> None:
    st = {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "NotResource": ["arn:aws:s3:::a", "arn:aws:s3:::b"],
    }
    assert pol.resources(st) == ["*"]


def test_resources_absent_entirely_is_empty() -> None:
    st = {"Effect": "Allow", "Action": "s3:GetObject"}
    assert pol.resources(st) == []


def test_resources_prefers_resource_over_not_resource_if_both_present() -> None:
    # Not a valid AWS shape (the two are mutually exclusive in practice), but
    # the reader should still behave deterministically rather than raise.
    st = {"Resource": ["arn:aws:s3:::b"], "NotResource": ["arn:aws:s3:::secret"]}
    assert pol.resources(st) == ["arn:aws:s3:::b"]
