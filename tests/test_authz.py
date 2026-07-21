"""Route-level RBAC enforcement tests (§10.2, Phase 4 Slice 2).

The route decorator (``app.web.authz.require_role``) is the primary gate —
these tests drive the real Flask routes as each of the three seeded roles via
the ``client``/``db_session`` fixtures (see conftest.py) and assert
allowed-vs-403, rather than testing the decorator in isolation. Bogus ids are
used throughout on purpose: proving a role gets PAST the decorator only needs
the response to not be 403 — the route's own downstream 404/302/400 is proof
enough that require_role let it through, without needing to fully exercise
each route's business logic (already covered by the service-layer tests) or
spin up a real background scan.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from app.models import AppUser, AuditEvent, FindingException, FindingGroup
from app.services import create_account, run_scan
from app.services.auth_service import DEMO_PASSWORD
from app.services.user_service import create_user
from sqlalchemy import select

pytestmark = pytest.mark.integration

_SAMPLES = Path(__file__).resolve().parent.parent / "samples"

_EMAIL = {
    "admin": "admin@example.com",
    "analyst": "analyst@example.com",
    "read_only": "viewer@example.com",
}
_ROLES = ("read_only", "analyst", "admin")


def _login(client, role: str):  # noqa: ANN001
    resp = client.post("/login", data={"email": _EMAIL[role], "password": DEMO_PASSWORD})
    assert resp.status_code == 302, f"login as {role} unexpectedly failed"
    return resp


def _seed(db_session):  # noqa: ANN001
    """A real completed scan + finding group, committed so the route layer's
    own session_scope() (a separate connection to the same file) sees it."""
    account = create_account(
        db_session,
        name="Acme Corp",
        source_type="file",
        source_config={
            "inventory_path": str(_SAMPLES / "users.csv"),
            "policies_path": str(_SAMPLES / "policies.json"),
            "logs_path": str(_SAMPLES / "auth.log"),
        },
    )
    run = run_scan(db_session, account.id)
    group_id = db_session.scalars(select(FindingGroup.id).order_by(FindingGroup.id)).first()
    assert group_id is not None
    return account.id, run.id, group_id


# ---- the route x minimum-role matrix ---------------------------------------
# (method, path, minimum_role, form_data) — a bogus/999999 id is used for
# every path-parameterized route (see module docstring); form data is the
# minimal shape each route's own validation expects before it would 404/400.
_BOGUS = 999999


def _matrix() -> list[tuple[str, str, str, dict]]:
    return [
        ("POST", "/accounts/connect", "admin", {"name": "", "method": "demo"}),
        ("POST", f"/accounts/{_BOGUS}/scan", "analyst", {}),
        ("POST", f"/accounts/{_BOGUS}/schedule", "analyst", {"cron": "0 2 * * *", "enabled": "on"}),
        ("POST", f"/accounts/{_BOGUS}/schedule/delete", "analyst", {}),
        ("POST", f"/accounts/{_BOGUS}/schedule/run-now", "analyst", {}),
        ("POST", f"/findings/{_BOGUS}/transition", "analyst", {"to_status": "investigating"}),
        ("POST", f"/findings/{_BOGUS}/suppress", "analyst", {"reason": "x"}),
        ("POST", f"/findings/{_BOGUS}/accept-risk", "admin", {"reason": "x"}),
        ("POST", f"/findings/{_BOGUS}/comment", "analyst", {"body": "x"}),
        ("POST", f"/findings/{_BOGUS}/assign", "analyst", {"assignee_id": "me"}),
        (
            "POST",
            "/findings/bulk/transition",
            "analyst",
            {"group_ids": "", "to_status": "investigating"},
        ),
        ("POST", "/findings/bulk/assign", "analyst", {"group_ids": "", "assignee_id": "me"}),
        ("POST", "/findings/bulk/suppress", "analyst", {"group_ids": "", "reason": "x"}),
        ("POST", "/findings/bulk/accept-risk", "admin", {"group_ids": "", "reason": "x"}),
        (
            "POST",
            f"/findings/{_BOGUS}/ticket",
            "analyst",
            {"target_id": "1", "title": "x", "body": "x"},
        ),
        ("GET", "/settings/users", "admin", {}),
        (
            "POST",
            "/settings/users",
            "admin",
            {"email": "", "display_name": "", "role": "read_only", "password": ""},
        ),
        ("POST", f"/settings/users/{_BOGUS}/role", "admin", {"role": "analyst"}),
        ("POST", f"/settings/users/{_BOGUS}/active", "admin", {"is_active": "0"}),
        ("GET", "/settings/integrations", "admin", {}),
        ("POST", "/settings/integrations", "admin", {"kind": "webhook", "name": "", "url": ""}),
        ("POST", f"/settings/integrations/{_BOGUS}/toggle", "admin", {"enabled": "1"}),
        ("POST", f"/settings/integrations/{_BOGUS}/delete", "admin", {}),
    ]


_MATRIX_IDS = [
    "connect",
    "scan",
    "schedule-save",
    "schedule-delete",
    "schedule-run-now",
    "transition",
    "suppress",
    "accept-risk",
    "comment",
    "assign",
    "bulk-transition",
    "bulk-assign",
    "bulk-suppress",
    "bulk-accept-risk",
    "ticket",
    "settings-users-list",
    "settings-users-create",
    "settings-users-role",
    "settings-users-active",
    "settings-integrations-list",
    "settings-integrations-create",
    "settings-integrations-toggle",
    "settings-integrations-delete",
]


@pytest.mark.parametrize("role", _ROLES)
@pytest.mark.parametrize(("idx",), [(i,) for i in range(len(_MATRIX_IDS))], ids=_MATRIX_IDS)
def test_route_x_role_matrix(client, db_session, role, idx) -> None:
    _seed(db_session)
    method, path, minimum, data = _matrix()[idx]
    _login(client, role)

    if method == "GET":
        resp = client.get(path, follow_redirects=False)
    else:
        resp = client.post(path, data=data, follow_redirects=False)

    allowed = _ROLES.index(role) >= _ROLES.index(minimum)
    if allowed:
        assert resp.status_code != 403, (
            f"{role} (>= {minimum}) was blocked from {method} {path}, expected pass-through"
        )
    else:
        assert resp.status_code == 403, f"{role} (< {minimum}) was NOT blocked from {method} {path}"


def test_403_writes_an_access_denied_audit_event(client, db_session) -> None:
    _login(client, "read_only")
    resp = client.post(f"/findings/{_BOGUS}/suppress", data={"reason": "x"})
    assert resp.status_code == 403

    events = db_session.scalars(
        select(AuditEvent).where(AuditEvent.action == "access_denied")
    ).all()
    assert len(events) == 1
    assert events[0].target == f"/findings/{_BOGUS}/suppress"
    assert events[0].event_metadata["required_role"] == "analyst"
    assert events[0].event_metadata["actual_role"] == "read_only"


def test_viewer_get_routes_remain_readable(client, db_session) -> None:
    """VIEW is read_only-level (§10.2) — a viewer must still be able to GET
    every page; only mutations (and the admin-only /settings/users) are
    gated."""
    _login(client, "read_only")
    for path in ("/", "/findings", "/accounts", "/runs", "/settings", "/profile"):
        resp = client.get(path)
        assert resp.status_code == 200, f"read_only was blocked from GET {path}"


def test_viewer_403_on_settings_users_but_profile_still_works(client, db_session) -> None:
    _login(client, "read_only")
    assert client.get("/settings/users").status_code == 403
    assert client.get("/profile").status_code == 200


# ---- named edge cases from the approved design -----------------------------


def test_suppress_is_analyst_but_accept_risk_is_admin(client, db_session) -> None:
    _, _, group_id = _seed(db_session)

    _login(client, "analyst")
    suppress = client.post(f"/findings/{group_id}/suppress", data={"reason": "known noise"})
    assert suppress.status_code != 403
    accept = client.post(f"/findings/{group_id}/accept-risk", data={"reason": "tracked elsewhere"})
    assert accept.status_code == 403


def test_reopening_accepted_risk_is_analyst_allowed(client, db_session) -> None:
    """Creating an accepted_risk exception is admin-only, but reopening one
    (a de-escalation) is analyst-allowed — the finding_transition route's
    to_status='open' path, gated only at WORKFLOW_TRANSITION=analyst."""
    _, _, group_id = _seed(db_session)

    _login(client, "admin")
    accept = client.post(f"/findings/{group_id}/accept-risk", data={"reason": "tracked elsewhere"})
    assert accept.status_code != 403
    group = db_session.get(FindingGroup, group_id)
    assert group.current_status == "accepted_risk"
    assert db_session.scalars(select(FindingException)).all()

    _login(client, "analyst")
    reopen = client.post(f"/findings/{group_id}/transition", data={"to_status": "open"})
    assert reopen.status_code != 403
    db_session.expire(group)
    assert group.current_status == "open"
    exc = db_session.scalars(select(FindingException)).one()
    assert exc.revoked_at is not None


def test_bulk_accept_risk_stays_admin_only_regardless_of_selection(client, db_session) -> None:
    """Bulk actions inherit their single-item gate (§10.2) — an analyst can't
    reach accepted_risk in bulk even with a real, non-empty selection."""
    _, _, group_id = _seed(db_session)
    _login(client, "analyst")
    resp = client.post(
        "/findings/bulk/accept-risk", data={"group_ids": str(group_id), "reason": "x"}
    )
    assert resp.status_code == 403
    group = db_session.get(FindingGroup, group_id)
    assert group.current_status == "open"  # nothing happened


def test_analyst_can_create_ticket_via_the_html_route(client, db_session) -> None:
    """CREATE_TICKET is analyst-level (§10.2/§7.5), unlike CONNECT_ACCOUNT/
    ACCEPT_RISK_CREATE — an analyst (not just admin) can actually create one."""
    from app.services.integration_service import create_target

    _, _, group_id = _seed(db_session)
    target = create_target(db_session, kind="jira", name="Jira", config={"project_key": "SEC"})
    db_session.commit()  # route layer opens its own connection to the same file

    _login(client, "analyst")
    resp = client.post(
        f"/findings/{group_id}/ticket",
        data={"target_id": str(target.id), "title": "MFA gap", "body": "details"},
    )
    assert resp.status_code == 200
    group = db_session.get(FindingGroup, group_id)
    db_session.refresh(group)
    assert group.ticket_ref is not None
    assert "(simulated)" in group.ticket_ref


def test_read_only_never_sees_a_mutating_control_in_the_drawer(client, db_session) -> None:
    """Server-rendered proxy for the Playwright "viewer sees zero action
    controls" check: the drawer partial itself must carry no action buttons
    and no assign/comment forms for a read_only viewer."""
    _, _, group_id = _seed(db_session)
    _login(client, "read_only")
    resp = client.get(f"/findings/{group_id}", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "No status actions available." in body
    assert 'name="body"' not in body  # comment box
    assert "Assign to me" not in body
    assert "Create ticket…" not in body


# ---- last-active-admin lockout (§10.3, Phase 4 Slice 3), route level ------


def _admin_id(db_session) -> int:  # noqa: ANN001
    admin_id = db_session.scalar(select(AppUser.id).where(AppUser.email == "admin@example.com"))
    assert admin_id is not None
    return admin_id


def test_route_blocks_deactivating_the_last_admin(client, db_session) -> None:
    admin_id = _admin_id(db_session)
    _login(client, "admin")

    resp = client.post(f"/settings/users/{admin_id}/active", data={"is_active": "0"})
    assert resp.status_code == 400
    assert b"last active admin" in resp.data

    user = db_session.get(AppUser, admin_id)
    db_session.refresh(user)
    assert user.is_active is True  # unchanged


def test_route_blocks_demoting_the_last_admin(client, db_session) -> None:
    admin_id = _admin_id(db_session)
    _login(client, "admin")

    resp = client.post(f"/settings/users/{admin_id}/role", data={"role": "analyst"})
    assert resp.status_code == 400
    assert b"last active admin" in resp.data

    user = db_session.get(AppUser, admin_id)
    db_session.refresh(user)
    assert user.role == "admin"  # unchanged


def test_route_allows_deactivating_a_non_last_admin(client, db_session) -> None:
    second_admin = create_user(
        db_session,
        email="second-admin@x.local",
        display_name="Second Admin",
        role="admin",
        password="a-long-password",
    )
    db_session.commit()  # route layer opens its own connection to the same file
    _login(client, "admin")

    resp = client.post(f"/settings/users/{second_admin.id}/active", data={"is_active": "0"})
    assert resp.status_code != 400
    db_session.refresh(second_admin)
    assert second_admin.is_active is False


def test_route_allows_demoting_a_non_last_admin(client, db_session) -> None:
    second_admin = create_user(
        db_session,
        email="second-admin@x.local",
        display_name="Second Admin",
        role="admin",
        password="a-long-password",
    )
    db_session.commit()  # route layer opens its own connection to the same file
    _login(client, "admin")

    resp = client.post(f"/settings/users/{second_admin.id}/role", data={"role": "analyst"})
    assert resp.status_code != 400
    db_session.refresh(second_admin)
    assert second_admin.role == "analyst"
