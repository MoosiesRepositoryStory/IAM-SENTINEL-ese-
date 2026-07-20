"""One full findings-workflow cycle, driven through the real drawer UI
(§7.1-§7.4, §8.8): transition, comment, assign, suppress.

Runs as analyst — every action below (WORKFLOW_TRANSITION/COMMENT/ASSIGN/
SUPPRESS) is analyst-capability; only accept-risk-creation is admin-only
(covered instead in test_auth_and_rbac.py, where it's the more relevant
thing to prove). Picks whichever finding is first under ``?status=open`` at
run time rather than a hardcoded id, so this test doesn't depend on test
execution order across the suite (some other test may have already mutated
one specific finding elsewhere; there are 44 seeded findings, so an open one
is always available).
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.e2e

_REASON = "E2E: known-accepted condition for this demo, suppressing."


def test_full_workflow_cycle_transition_comment_assign_suppress(
    page: Page, base_url: str, login_as
) -> None:
    login_as("analyst")
    page.goto(f"{base_url}/findings?status=open")
    page.locator("tr[data-group-id]").first.click()
    expect(page.locator(".drawer-panel")).to_be_visible()

    # -- Assign --------------------------------------------------------
    page.get_by_role("button", name="Assign to me").click()
    expect(page.locator(".assignee-cell")).to_contain_text("Demo Analyst")

    # -- Transition (open -> investigating) -----------------------------
    page.get_by_role("button", name="Start investigating").click()
    expect(page.locator("#drawer-status")).to_contain_text("Investigating")

    # -- Comment (Activity tab) ------------------------------------------
    page.get_by_role("button", name="Activity", exact=False).click()
    page.locator("[id^='comment-']").fill("Confirmed via CloudTrail, escalating to suppress.")
    page.get_by_role("button", name="Comment").click()
    expect(page.locator(".tl-comment")).to_contain_text("Confirmed via CloudTrail")

    # -- Back to open, then suppress --------------------------------------
    # Suppress is only offered from `open` (see workflow_service.
    # TRANSITION_ACTIONS) — Reopen first, matching a real analyst's path:
    # investigate, decide it's a known/accepted condition, suppress it.
    page.get_by_role("button", name="Reopen").click()
    expect(page.locator("#drawer-status")).to_contain_text("Open")

    page.get_by_role("button", name="Suppress", exact=True).click()
    page.get_by_placeholder("Reason for suppression (required)").fill(_REASON)
    page.get_by_role("button", name="Confirm suppress").click()

    expect(page.locator("#drawer-status")).to_contain_text("Suppressed")
    expect(page.locator(".exception-panel")).to_be_visible()
    expect(page.locator(".exc-reason")).to_contain_text(_REASON)

    # Reopen offered as the only action from a suppressed state (§7.1).
    expect(page.get_by_role("button", name="Reopen")).to_be_visible()
