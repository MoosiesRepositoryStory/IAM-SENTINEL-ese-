"""Login/logout + RBAC gating across all three seeded demo roles (§10.1/§10.2).

Complements the Flask-test-client unit suites (tests/test_auth_web.py,
tests/test_authz.py), which already prove every route's 403 boundary
exhaustively — that's not worth re-driving through a real browser. What only
a real browser proves: a login round-trip leaves you with a genuinely
working session (not just a 200 from the login route), and the UI itself
*hides* controls a role can't use rather than rendering them disabled/inert.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.e2e


def test_login_logout_roundtrip(page: Page, base_url: str, login_as) -> None:
    login_as("admin")
    expect(page.locator(".user-chip-name")).to_have_text("Demo Admin")

    page.get_by_role("button", name="Sign out").click()
    expect(page).to_have_url(re.compile(r"/login$"))

    # The session is really gone server-side, not just a client redirect: a
    # protected page now bounces back to the login form instead of rendering.
    page.goto(f"{base_url}/findings")
    expect(page).to_have_url(re.compile(r"/login"))


def test_login_rejects_wrong_password(page: Page, base_url: str) -> None:
    page.goto(f"{base_url}/login")
    page.get_by_label("Email").fill("admin@example.com")
    page.get_by_label("Password").fill("not-the-real-password")
    page.get_by_role("button", name="Sign in").click()
    expect(page.locator(".login-error")).to_be_visible()
    expect(page).to_have_url(re.compile(r"/login"))


def test_read_only_sees_no_mutating_controls_and_is_blocked_from_admin_settings(
    page: Page, base_url: str, login_as
) -> None:
    login_as("read_only")
    page.goto(f"{base_url}/findings?status=open")
    page.locator("tr[data-group-id]").first.click()
    expect(page.locator(".drawer-panel")).to_be_visible()

    # §10.2: read_only gets zero transition/comment/assign controls — the
    # drawer footer falls back to its no-actions message.
    expect(page.locator(".drawer-foot")).to_contain_text("No status actions available")
    expect(page.get_by_role("button", name="Suppress", exact=True)).to_have_count(0)
    expect(page.get_by_role("button", name="Assign to me")).to_have_count(0)

    response = page.goto(f"{base_url}/settings/users")
    assert response is not None and response.status == 403


def test_analyst_can_mutate_but_not_accept_risk_or_manage_users(
    page: Page, base_url: str, login_as
) -> None:
    login_as("analyst")
    page.goto(f"{base_url}/findings?status=open")
    page.locator("tr[data-group-id]").first.click()
    expect(page.get_by_role("button", name="Start investigating")).to_be_visible()
    expect(page.get_by_role("button", name="Suppress", exact=True)).to_be_visible()

    # §10.2's admin-only carve-out: analyst can de-escalate an existing
    # risk-acceptance (Reopen) but never create a new one.
    expect(page.get_by_role("button", name="Accept risk")).to_have_count(0)

    response = page.goto(f"{base_url}/settings/users")
    assert response is not None and response.status == 403


def test_admin_has_full_findings_and_settings_access(page: Page, base_url: str, login_as) -> None:
    login_as("admin")
    page.goto(f"{base_url}/findings?status=open")
    page.locator("tr[data-group-id]").first.click()
    expect(page.get_by_role("button", name="Accept risk")).to_be_visible()

    response = page.goto(f"{base_url}/settings/users")
    assert response is not None and response.status == 200
    expect(page.locator("h1")).to_have_text("Users")
