"""Pure role-ladder logic (§10.2, Phase 4 Slice 2). Route/service-level
enforcement is covered by test_authz.py, test_exception_service.py, and
test_connect_service.py — this file is just the ladder function itself.
"""

from __future__ import annotations

import pytest
from app.services.rbac import Capability, at_least


@pytest.mark.parametrize(
    ("role", "minimum", "expected"),
    [
        ("admin", "read_only", True),
        ("admin", "analyst", True),
        ("admin", "admin", True),
        ("analyst", "read_only", True),
        ("analyst", "analyst", True),
        ("analyst", "admin", False),
        ("read_only", "read_only", True),
        ("read_only", "analyst", False),
        ("read_only", "admin", False),
    ],
)
def test_at_least_ladder(role, minimum, expected) -> None:
    assert at_least(role, minimum) is expected


def test_at_least_unknown_role_satisfies_nothing() -> None:
    assert at_least("superuser", "read_only") is False
    assert at_least("", "read_only") is False


def test_at_least_none_role_satisfies_nothing() -> None:
    assert at_least(None, "read_only") is False


def test_capability_matrix_matches_the_approved_design() -> None:
    """Pins the agreed matrix (§10.2) so a future edit that accidentally
    loosens a capability is caught here, not just in a route test."""
    assert Capability.VIEW == "read_only"
    assert Capability.RUN_SCAN == "analyst"
    assert Capability.MANAGE_SCHEDULE == "analyst"
    assert Capability.CONNECT_ACCOUNT == "admin"
    assert Capability.WORKFLOW_TRANSITION == "analyst"
    assert Capability.ASSIGN == "analyst"
    assert Capability.COMMENT == "analyst"
    assert Capability.SUPPRESS == "analyst"
    assert Capability.ACCEPT_RISK_CREATE == "admin"
