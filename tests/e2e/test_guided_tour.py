"""Guided tour (Sentinel.startTour) — launched manually from the top-right
menu, stepped through, and ended early via Escape.

The load-bearing assertion is the LAST one: after the tour ends, a real
click on an element that was behind the tour backdrop still works (opens the
finding drawer). That proves the overlay is genuinely gone and nothing
lingers intercepting clicks — the exact failure mode a full-viewport overlay
with mishandled pointer-events would cause (cf. the drawer-skeleton bug
fixed earlier this session), which asserting only that the tour's own
elements disappeared visually would NOT catch.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.e2e


def _launch_tour(page: Page) -> None:
    page.locator('[data-tour="menu"]').click()
    page.get_by_role("menuitem", name="Start tutorial").click()
    expect(page.locator(".tour-backdrop")).to_be_visible()


def test_tour_opens_steps_and_ends_via_escape_leaving_app_interactive(
    page: Page, base_url: str, login_as
) -> None:
    login_as("analyst")
    page.goto(f"{base_url}/findings?status=open")
    expect(page.locator("tr[data-group-id]").first).to_be_visible()

    # It is NOT auto-launched — nothing tour-related exists until the menu
    # item is clicked. (An auto-tour would break every other E2E test.)
    expect(page.locator(".tour-backdrop")).to_have_count(0)

    _launch_tour(page)
    expect(page.locator(".tour-tip-title")).to_have_text("Welcome to IAM Sentinel")
    expect(page.locator(".tour-step-count")).to_contain_text("1 / ")

    # Step forward twice; the anchored steps show the spotlight.
    page.get_by_role("button", name="Next", exact=True).click()
    expect(page.locator(".tour-tip-title")).to_have_text("Navigation")
    expect(page.locator(".tour-spotlight")).to_be_visible()
    page.get_by_role("button", name="Next", exact=True).click()
    expect(page.locator(".tour-tip-title")).to_have_text("Search and filter")

    # Back returns to the previous step.
    page.get_by_role("button", name="Back", exact=True).click()
    expect(page.locator(".tour-tip-title")).to_have_text("Navigation")

    # Escape ends the tour — every tour node is removed from the DOM, not
    # merely hidden.
    page.keyboard.press("Escape")
    expect(page.locator(".tour-backdrop")).to_have_count(0)
    expect(page.locator(".tour-spotlight")).to_have_count(0)
    expect(page.locator(".tour-tooltip")).to_have_count(0)

    # The real payoff: click a finding row that sat behind the backdrop and
    # confirm the app responds (drawer opens) — i.e. clicks reach the page,
    # nothing left over is eating them.
    page.locator("tr[data-group-id]").first.click()
    expect(page.locator(".drawer-panel")).to_be_visible()


def test_tour_ends_by_clicking_the_backdrop(page: Page, base_url: str, login_as) -> None:
    login_as("analyst")
    page.goto(f"{base_url}/findings?status=open")
    expect(page.locator("tr[data-group-id]").first).to_be_visible()

    _launch_tour(page)
    # First step is centered, so the tooltip is dead-center; click a far
    # corner of the backdrop (well clear of it) to exercise the
    # click-to-dismiss path.
    page.locator(".tour-backdrop").click(position={"x": 6, "y": 6})
    expect(page.locator(".tour-backdrop")).to_have_count(0)

    # Still interactive afterward.
    page.locator("tr[data-group-id]").first.click()
    expect(page.locator(".drawer-panel")).to_be_visible()
