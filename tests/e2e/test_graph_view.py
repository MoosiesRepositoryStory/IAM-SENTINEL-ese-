"""Blast-radius graph rendering (§6.2) — asserts a real, populated Cytoscape
instance via the app's own ``window.__sentinelCy`` test hook
(app/web/static/js/graph.js), the same hook prior ad hoc Playwright passes
used, not just that the page's markup is present.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.e2e


def test_graph_overview_lists_principals_and_links_to_detail(
    page: Page, base_url: str, login_as
) -> None:
    login_as("analyst")
    page.goto(f"{base_url}/graph")

    rows = page.locator("table.findings tbody tr")
    expect(rows.first).to_be_visible()
    assert rows.count() > 0

    rows.first.click()
    expect(page).to_have_url(re.compile(r"/principals/"))
    expect(page.locator("#cy")).to_be_visible()


def test_principal_detail_renders_a_real_cytoscape_graph_with_escalation_path(
    page: Page, base_url: str, login_as
) -> None:
    login_as("analyst")
    # intern's escalation path (intern -> bob via CreateAccessKey, Phase 3
    # Slice 1) is a deterministic property of the moto seed — navigate via
    # the overview rather than guessing intern's exact principal_uid/ARN
    # URL-encoding.
    page.goto(f"{base_url}/graph")
    page.get_by_role("row", name=re.compile("intern", re.IGNORECASE)).click()

    expect(page.locator(".escalation-banner")).to_be_visible()
    expect(page.locator(".escalation-banner")).to_contain_text("bob")

    page.wait_for_function("window.__sentinelCy && window.__sentinelCy.nodes().length > 0")
    node_count = page.evaluate("window.__sentinelCy.nodes().length")
    edge_count = page.evaluate("window.__sentinelCy.edges().length")
    assert node_count > 0, "expected a real, populated Cytoscape graph"
    assert edge_count > 0, "expected real edges, not just an isolated node"
