"""Run-to-run diff view (§5.4/§8.9), rendered against real drift from the
seeded moto org's two scans (see seed.py) — not a hand-built fixture, so this
proves the whole path: DiffService's on-demand computation, the three-column
board template, and the summary banner, wired together against genuine
persisted runs.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.e2e


def _column_count(page: Page, key: str) -> int:
    return int(page.locator(f".diff-col.diff-{key} .dcol-count").inner_text())


def test_diff_view_shows_real_drift_between_the_two_seeded_runs(
    page: Page, base_url: str, login_as
) -> None:
    login_as("analyst")
    # No ?a=&b= — views.runs_diff's default_diff_pair() picks previous-vs-
    # latest completed, which for a freshly seeded account is exactly the
    # two scans seed.py just ran.
    page.goto(f"{base_url}/runs/diff")

    expect(page.locator(".diff-banner")).to_be_visible()
    expect(page.locator(".empty")).to_have_count(0)  # not the "nothing to compare" state

    new_count = _column_count(page, "new")
    resolved_count = _column_count(page, "resolved")
    assert new_count > 0, "seeded drift (Phase 2 Slice 4) should produce at least one New finding"
    assert resolved_count > 0, "seeded drift should produce at least one Resolved finding"

    expect(page.locator(".diff-col.diff-new .dcol-body")).not_to_contain_text("None")
    expect(page.locator(".diff-col.diff-resolved .dcol-body")).not_to_contain_text("None")

    # Score-trend sparkline only renders with >1 completed run in history.
    expect(page.locator(".spark")).to_be_visible()
