"""Shared fixtures for the Playwright E2E suite (see README.md).

Deliberately imports only ``DEMO_USERS``/``DEMO_PASSWORD`` from the app —
the single source of truth for the seeded login credentials, so this suite
can't silently drift from whatever ``auth_service`` actually seeds. Every
other interaction goes through the real HTTP/browser interface, the same as
a real user would use it — no route-internal shortcuts.

Requires ``--base-url`` (pytest-playwright's own option) pointing at a
already-running, already-seeded server — see README.md for the local and CI
invocations. Nothing here starts or seeds that server itself.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from app.services.auth_service import DEMO_PASSWORD, DEMO_USERS
from playwright.sync_api import Page

_ROLE_EMAILS: dict[str, str] = {role: email for email, _display_name, role in DEMO_USERS}


@pytest.fixture
def login_as(page: Page, base_url: str) -> Callable[[str], None]:
    """Returns a function that logs ``page`` in as the seeded demo account
    for ``role`` ("read_only" / "analyst" / "admin"), through the real login
    form — waits for the post-login chrome to render rather than a specific
    URL, since ``web.index`` is reachable at both ``/`` and ``/dashboard``."""

    def _login(role: str) -> None:
        page.goto(f"{base_url}/login")
        page.get_by_label("Email").fill(_ROLE_EMAILS[role])
        page.get_by_label("Password").fill(DEMO_PASSWORD)
        page.get_by_role("button", name="Sign in").click()
        page.wait_for_selector(".user-chip-name")

    return _login
