"""Integration-target admin CRUD tests (§7.5, Phase 4 Slice 5)."""

from __future__ import annotations

import pytest
from app.models import AuditEvent, IntegrationTarget
from app.services.integration_service import (
    IntegrationError,
    create_target,
    delete_target,
    list_enabled_targets,
    list_targets,
    set_enabled,
)
from sqlalchemy import select


def test_create_webhook_target(db_session) -> None:
    target = create_target(
        db_session, kind="webhook", name="Triage hook",
        config={"url": "https://example.com/hook"},
    )
    assert target.id is not None
    assert target.enabled is True
    row = db_session.get(IntegrationTarget, target.id)
    assert row.config == {"url": "https://example.com/hook"}
    event = db_session.scalars(select(AuditEvent).where(AuditEvent.action == "integration_created")).one()
    assert event.event_metadata["kind"] == "webhook"


def test_create_target_requires_name(db_session) -> None:
    with pytest.raises(IntegrationError, match="Name is required"):
        create_target(db_session, kind="webhook", name="  ", config={"url": "https://x"})


def test_create_target_unknown_kind_rejected(db_session) -> None:
    with pytest.raises(IntegrationError, match="Unknown integration kind"):
        create_target(db_session, kind="carrier-pigeon", name="x", config={})


def test_webhook_target_requires_url(db_session) -> None:
    with pytest.raises(IntegrationError, match="require a 'url'"):
        create_target(db_session, kind="webhook", name="No URL", config={})


def test_jira_and_slack_have_no_required_field(db_session) -> None:
    # project_key/channel both fall back to sensible defaults in the
    # adapters themselves (see test_integration_adapters.py) — the admin
    # form doesn't need to force one.
    jira = create_target(db_session, kind="jira", name="Jira", config={})
    slack = create_target(db_session, kind="slack", name="Slack", config={})
    assert jira.id is not None
    assert slack.id is not None


def test_list_enabled_targets_excludes_disabled(db_session) -> None:
    a = create_target(db_session, kind="webhook", name="A", config={"url": "https://a"})
    create_target(db_session, kind="webhook", name="B", config={"url": "https://b"})
    set_enabled(db_session, a.id, False)

    enabled = list_enabled_targets(db_session)
    assert [t.name for t in enabled] == ["B"]
    assert len(list_targets(db_session)) == 2


def test_set_enabled_unknown_target_raises(db_session) -> None:
    with pytest.raises(IntegrationError, match="not found"):
        set_enabled(db_session, 999999, True)


def test_delete_target(db_session) -> None:
    target = create_target(db_session, kind="webhook", name="A", config={"url": "https://a"})
    delete_target(db_session, target.id)
    assert db_session.get(IntegrationTarget, target.id) is None
    event = db_session.scalars(select(AuditEvent).where(AuditEvent.action == "integration_deleted")).one()
    assert event.event_metadata["name"] == "A"


def test_delete_unknown_target_raises(db_session) -> None:
    with pytest.raises(IntegrationError, match="not found"):
        delete_target(db_session, 999999)
