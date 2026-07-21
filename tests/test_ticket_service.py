"""``ticket_service.create_ticket`` tests (§7.5, Phase 4 Slice 5) — the
orchestration layer between a resolved finding, a configured
``IntegrationTarget``, and the adapter registry. Uses a real seeded scan
(same pattern as ``test_api_endpoints.py``) so ``group``/``finding`` are
genuine ORM rows, not hand-built fixtures.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from app.models import AppUser, AuditEvent, Finding, FindingGroup
from app.services import create_account, run_scan
from app.services.integration_service import create_target
from app.services.ticket_service import TicketError, create_ticket
from sqlalchemy import select

pytestmark = pytest.mark.integration

_SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def _seed(session) -> tuple[FindingGroup, Finding]:
    account = create_account(
        session,
        name="Acme Corp",
        source_type="file",
        source_config={
            "inventory_path": str(_SAMPLES / "users.csv"),
            "policies_path": str(_SAMPLES / "policies.json"),
            "logs_path": str(_SAMPLES / "auth.log"),
        },
    )
    run_scan(session, account.id)
    group = session.scalars(select(FindingGroup).order_by(FindingGroup.id)).first()
    finding = session.scalars(
        select(Finding).where(Finding.group_id == group.id).order_by(Finding.id.desc())
    ).first()
    assert group is not None and finding is not None
    return group, finding


def test_create_ticket_via_jira_stub_persists_ref(db_session) -> None:
    group, finding = _seed(db_session)
    target = create_target(db_session, kind="jira", name="Jira", config={"project_key": "SEC"})
    actor = AppUser(email="a@x.io", display_name="Analyst", password_hash="!", role="analyst")
    db_session.add(actor)
    db_session.flush()

    used = create_ticket(
        db_session,
        group,
        finding,
        target_id=target.id,
        title="MFA gap",
        body="details",
        finding_url="https://sentinel.example/findings/1",
        actor_id=actor.id,
    )
    assert used.id == target.id
    db_session.refresh(group)
    assert group.ticket_ref is not None
    assert "(simulated)" in group.ticket_ref
    assert group.ticket_url is None

    event = db_session.scalars(
        select(AuditEvent).where(AuditEvent.action == "ticket_created")
    ).one()
    assert event.event_metadata["kind"] == "jira"
    assert event.event_metadata["simulated"] is True
    assert event.actor_id == actor.id


def test_create_ticket_requires_title(db_session) -> None:
    group, finding = _seed(db_session)
    target = create_target(db_session, kind="jira", name="Jira", config={})
    with pytest.raises(TicketError, match="title is required"):
        create_ticket(
            db_session,
            group,
            finding,
            target_id=target.id,
            title="   ",
            body="",
            finding_url="https://x",
        )
    db_session.refresh(group)
    assert group.ticket_ref is None  # nothing persisted on a rejected request


def test_create_ticket_unknown_target_raises(db_session) -> None:
    group, finding = _seed(db_session)
    with pytest.raises(TicketError, match="not found"):
        create_ticket(
            db_session,
            group,
            finding,
            target_id=999999,
            title="x",
            body="",
            finding_url="https://x",
        )


def test_create_ticket_disabled_target_rejected(db_session) -> None:
    group, finding = _seed(db_session)
    target = create_target(db_session, kind="jira", name="Jira", config={})
    target.enabled = False
    db_session.flush()

    with pytest.raises(TicketError, match="disabled"):
        create_ticket(
            db_session,
            group,
            finding,
            target_id=target.id,
            title="x",
            body="",
            finding_url="https://x",
        )


def test_create_ticket_rejects_when_ticket_ref_already_set(db_session) -> None:
    """A retry (double-click, client timeout on a request that actually
    succeeded server-side) must not call the adapter a second time — that
    would create a genuine second ticket in the external system rather than
    just re-showing the first one."""
    group, finding = _seed(db_session)
    target = create_target(db_session, kind="jira", name="Jira", config={"project_key": "SEC"})
    create_ticket(
        db_session,
        group,
        finding,
        target_id=target.id,
        title="MFA gap",
        body="details",
        finding_url="https://x",
    )
    db_session.refresh(group)
    first_ref = group.ticket_ref
    assert first_ref is not None

    with pytest.raises(TicketError, match="already exists"):
        create_ticket(
            db_session,
            group,
            finding,
            target_id=target.id,
            title="MFA gap (retry)",
            body="details",
            finding_url="https://x",
        )

    db_session.refresh(group)
    assert group.ticket_ref == first_ref  # unchanged — no second ticket, no overwrite
    events = db_session.scalars(
        select(AuditEvent).where(AuditEvent.action == "ticket_created")
    ).all()
    assert len(events) == 1


def test_create_ticket_via_webhook_target(
    db_session, local_http_server, allow_loopback_webhook_targets
) -> None:
    group, finding = _seed(db_session)
    url = f"http://127.0.0.1:{local_http_server.server_port}/hook"
    target = create_target(db_session, kind="webhook", name="Hook", config={"url": url})

    create_ticket(
        db_session,
        group,
        finding,
        target_id=target.id,
        title="MFA gap",
        body="details",
        finding_url="https://sentinel.example/findings/1",
    )
    db_session.refresh(group)
    assert group.ticket_ref.startswith("webhook-")
    assert group.ticket_url is None
