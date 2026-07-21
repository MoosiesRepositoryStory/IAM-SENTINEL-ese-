"""Copy-to-clipboard affordance (Sentinel.copyValue) on hard-to-select
values — the finding drawer's principal ARN here, standing in for every
other spot using the same reusable button.

Deliberately asserts on the button's own visible feedback (aria-label/class
swapping to "copied" and back), not on reading the clipboard back:
clipboard-*read* permission grants are the genuinely flaky one across
browsers/headless CI environments, so this suite never asks for it.

clipboard-*write* is a different, narrower permission — headless Chromium
here defaults it to "prompt" (verified: an ungranted writeText() rejects
with NotAllowedError), but explicitly granting just that one permission via
Playwright's own context.grant_permissions() is the standard, non-flaky way
every Playwright clipboard-button test does this, and is what actually
exercises the real code path (navigator.clipboard.writeText, same as
production) rather than mocking it away.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.e2e


def test_copy_button_shows_and_reverts_its_own_confirmation(
    page: Page, base_url: str, login_as
) -> None:
    page.context.grant_permissions(["clipboard-write"], origin=base_url)
    login_as("analyst")
    # Filter to a principal-bearing finding specifically (some seeded
    # findings are policy-level, not principal-level, and have no
    # principal_uid / no "Copy principal" button — "intern" is a real
    # seeded principal, same reliable anchor test_finding_query.py already
    # uses, so this is deterministic rather than depending on whichever
    # finding happens to sort first under ?status=open alone).
    page.goto(f"{base_url}/findings?status=open&q=intern")
    page.locator("tr[data-group-id]").first.click()
    expect(page.locator(".drawer-panel")).to_be_visible()

    copy_btn = page.locator(".drawer-sub .copy-btn").first
    expect(copy_btn).to_have_attribute("aria-label", "Copy principal")

    copy_btn.click()
    expect(copy_btn).to_have_attribute("aria-label", "Copied")
    expect(copy_btn).to_have_class(re.compile(r"\bcopied\b"))

    # Reverts on its own after ~1.5s — Playwright's default 5s assertion
    # timeout covers the wait without a manual sleep.
    expect(copy_btn).to_have_attribute("aria-label", "Copy principal", timeout=5000)
    expect(copy_btn).not_to_have_class(re.compile(r"\bcopied\b"))
