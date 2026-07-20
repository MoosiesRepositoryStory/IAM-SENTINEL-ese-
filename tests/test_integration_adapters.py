"""Ticket adapter tests (§7.5, Phase 4 Slice 5).

``WebhookAdapter`` is the one adapter that actually performs network I/O, so
it's tested against a REAL local HTTP server (a background thread, not a
mock) — proving the JSON POST genuinely leaves the process, matching this
adapter's whole reason for existing ("should actually function, not be a
stub"). ``JiraAdapter``/``SlackAdapter`` are permanent, honest stubs (see
their own module docstrings for why) — tested for the shape of the payload
they'd send and the clearly-labeled simulated ref they return instead.
"""

from __future__ import annotations

import pytest
from app.integrations.base import FindingView, IntegrationError
from app.integrations.jira import JiraAdapter
from app.integrations.registry import ADAPTERS, KINDS, UnknownIntegrationKind, get_adapter
from app.integrations.slack import SlackAdapter
from app.integrations.webhook import WebhookAdapter

from tests.conftest import CapturingHandler


def _finding_view(**overrides) -> FindingView:
    base = {
        "group_id": 42,
        "check_id": "iam.mfa.console_no_mfa",
        "severity": "HIGH",
        "category": "identity",
        "principal_uid": "user/intern",
        "resource": None,
        "recommendation": "Enforce MFA for console access.",
        "finding_url": "https://sentinel.example/findings/42",
    }
    base.update(overrides)
    return FindingView(**base)


# ---- registry ----------------------------------------------------------


def test_registry_has_all_three_kinds() -> None:
    assert set(KINDS) == {"webhook", "jira", "slack"}
    assert ADAPTERS["webhook"] is WebhookAdapter
    assert ADAPTERS["jira"] is JiraAdapter
    assert ADAPTERS["slack"] is SlackAdapter


def test_get_adapter_unknown_kind_raises() -> None:
    with pytest.raises(UnknownIntegrationKind):
        get_adapter("carrier-pigeon")


def test_get_adapter_returns_a_fresh_instance() -> None:
    a = get_adapter("webhook")
    b = get_adapter("webhook")
    assert isinstance(a, WebhookAdapter)
    assert a is not b


# ---- WebhookAdapter: real HTTP, not mocked (server fixture in conftest.py) --


def test_webhook_adapter_really_posts_json(local_http_server, allow_loopback_webhook_targets) -> None:
    url = f"http://127.0.0.1:{local_http_server.server_port}/hooks/sentinel"
    adapter = WebhookAdapter()
    ref = adapter.create_ticket(
        _finding_view(), {"url": url}, title="Console access without MFA", body="See finding."
    )

    assert ref.simulated is False
    assert ref.ref.startswith("webhook-")

    assert len(CapturingHandler.received) == 1
    call = CapturingHandler.received[0]
    assert call["path"] == "/hooks/sentinel"
    assert call["headers"]["Content-Type"] == "application/json"
    assert call["json"]["ref"] == ref.ref
    assert call["json"]["title"] == "Console access without MFA"
    assert call["json"]["finding"]["group_id"] == 42
    assert call["json"]["finding"]["check_id"] == "iam.mfa.console_no_mfa"
    assert call["json"]["finding"]["url"] == "https://sentinel.example/findings/42"


def test_webhook_adapter_missing_url_raises(local_http_server) -> None:
    adapter = WebhookAdapter()
    with pytest.raises(IntegrationError, match="no URL configured"):
        adapter.create_ticket(_finding_view(), {}, title="x", body="")


def test_webhook_adapter_non_2xx_raises(local_http_server, allow_loopback_webhook_targets) -> None:
    CapturingHandler.respond_status = 500
    url = f"http://127.0.0.1:{local_http_server.server_port}/hooks/sentinel"
    adapter = WebhookAdapter()
    with pytest.raises(IntegrationError, match="HTTP 500"):
        adapter.create_ticket(_finding_view(), {"url": url}, title="x", body="")


def test_webhook_adapter_connection_refused_raises(allow_loopback_webhook_targets) -> None:
    # Port 1 is a real, always-unreachable "well known" TCP port for a
    # userland process — a genuine connection failure, not a mock.
    adapter = WebhookAdapter()
    with pytest.raises(IntegrationError, match="Could not reach"):
        adapter.create_ticket(
            _finding_view(), {"url": "http://127.0.0.1:1/hooks"}, title="x", body=""
        )


# ---- WebhookAdapter: SSRF guard (§7.5 hardening) ---------------------------


def test_webhook_adapter_rejects_unsupported_scheme() -> None:
    adapter = WebhookAdapter()
    with pytest.raises(IntegrationError, match="unsupported URL scheme"):
        adapter.create_ticket(_finding_view(), {"url": "file:///etc/passwd"}, title="x", body="")


def test_webhook_adapter_rejects_loopback_target_by_default() -> None:
    """Without the test-only bypass fixture, the real guard is live — the
    exact property that fixture exists to override just for the local-server
    tests above."""
    adapter = WebhookAdapter()
    with pytest.raises(IntegrationError, match="disallowed address"):
        adapter.create_ticket(_finding_view(), {"url": "http://127.0.0.1:1/hooks"}, title="x", body="")


def test_webhook_adapter_rejects_cloud_metadata_style_target(monkeypatch) -> None:
    """A hostname that resolves to the AWS/GCP/Azure metadata address
    (169.254.169.254, link-local) must be rejected before any connection is
    attempted — the concrete "intranet/metadata access" risk the audit
    flagged for an admin-configured webhook in a public deployment."""
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda host, *a, **kw: [(2, 1, 6, "", ("169.254.169.254", 0))],
    )
    adapter = WebhookAdapter()
    with pytest.raises(IntegrationError, match="disallowed address"):
        adapter.create_ticket(
            _finding_view(), {"url": "http://internal-service.example/hooks"}, title="x", body=""
        )


# ---- JiraAdapter: permanent honest stub ------------------------------------


def test_jira_adapter_returns_labeled_simulated_ref() -> None:
    adapter = JiraAdapter()
    ref = adapter.create_ticket(
        _finding_view(group_id=7), {"project_key": "SEC"}, title="MFA gap", body="details"
    )
    assert ref.simulated is True
    assert ref.ref == "SEC-1007 (simulated)"
    assert "(simulated)" in ref.ref
    assert ref.url is None


def test_jira_adapter_defaults_project_key_when_missing() -> None:
    adapter = JiraAdapter()
    ref = adapter.create_ticket(_finding_view(group_id=1), {}, title="x", body="")
    assert ref.ref.startswith("SEC-")


# ---- SlackAdapter: permanent honest stub -----------------------------------


def test_slack_adapter_returns_labeled_simulated_ref() -> None:
    adapter = SlackAdapter()
    ref = adapter.create_ticket(
        _finding_view(group_id=9), {"channel": "#iam-alerts"}, title="MFA gap", body="details"
    )
    assert ref.simulated is True
    assert "#iam-alerts" in ref.ref
    assert "(simulated)" in ref.ref
    assert ref.url is None


def test_slack_adapter_defaults_channel_when_missing() -> None:
    adapter = SlackAdapter()
    ref = adapter.create_ticket(_finding_view(), {}, title="x", body="")
    assert "#security-alerts" in ref.ref
