"""Mutating /api/v1 surface tests (§10.4, Phase 4 Slice 4b) — connect/scan/
schedule + findings workflow (transition/suppress/accept-risk/comment/assign,
single + bulk), all over the JWT-authed API. Mirrors two existing suites:
``test_api_endpoints.py``'s request/response conventions (JSON, bearer auth,
error envelope) and ``test_authz.py``'s role-matrix approach (bogus ids are
enough to prove a role got PAST the gate — the route's own downstream
404/409/400 is proof enough, no need to fully exercise business logic already
covered by the HTML-route/service-layer tests).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from app.db import session_scope
from app.jobs import get_job_queue, set_job_queue
from app.models import Account, FindingException, FindingGroup, Schedule
from app.services import create_account, run_scan
from app.services.auth_service import DEMO_PASSWORD
from sqlalchemy import select

pytestmark = pytest.mark.integration

_SAMPLES = Path(__file__).resolve().parent.parent / "samples"
_EMAILS = {
    "admin": "admin@example.com",
    "analyst": "analyst@example.com",
    "read_only": "viewer@example.com",
}
_ROLES = ("read_only", "analyst", "admin")
_BOGUS = 999999


def _token(client, role: str = "admin") -> str:  # noqa: ANN001
    resp = client.post(
        "/api/v1/auth/login", json={"email": _EMAILS[role], "password": DEMO_PASSWORD}
    )
    assert resp.status_code == 200
    return resp.get_json()["token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _seed(db_session) -> dict:  # noqa: ANN001
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
    return {"account_id": account.id, "run_id": run.id, "group_id": group_id}


class _RecordingJobQueue:
    """Same seam ``test_scan_service.py``/``test_scheduler.py`` already use:
    captures the submitted job instead of running it on a real background
    thread, so a test can assert the pre-execution state, then drive it to
    completion deterministically by calling it directly."""

    def __init__(self) -> None:
        self.jobs: list[Callable[[], None]] = []

    def submit(self, fn: Callable[[], None]) -> None:
        self.jobs.append(fn)


@pytest.fixture
def job_queue_spy():
    original = get_job_queue()
    spy = _RecordingJobQueue()
    set_job_queue(spy)
    try:
        yield spy
    finally:
        set_job_queue(original)


def _run_jobs(spy: _RecordingJobQueue) -> None:
    for job in spy.jobs:
        job()
    spy.jobs.clear()


# ---- accounts: connect ------------------------------------------------------


def test_connect_account_upload_method(client, db_session, job_queue_spy) -> None:
    token = _token(client, "admin")
    payload = {
        "name": "Acme Corp",
        "method": "upload",
        "inventory_text": (_SAMPLES / "users.csv").read_text(),
        "policies_json": (_SAMPLES / "policies.json").read_text(),
        "logs_text": (_SAMPLES / "auth.log").read_text(),
    }
    resp = client.post("/api/v1/accounts/connect", json=payload, headers=_auth(token))
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["account_id"] is not None
    assert body["run_id"] is not None
    assert body["schedule_id"] is None

    account = db_session.get(Account, body["account_id"])
    assert account is not None
    assert account.source_type == "file"

    _run_jobs(job_queue_spy)
    with session_scope() as session:
        assert (
            session.scalars(
                select(FindingGroup).where(FindingGroup.account_id == body["account_id"])
            ).first()
            is not None
        )


def test_connect_account_with_schedule(client, db_session, job_queue_spy) -> None:
    token = _token(client, "admin")
    payload = {
        "name": "Acme Corp",
        "method": "upload",
        "inventory_text": (_SAMPLES / "users.csv").read_text(),
        "schedule_enabled": True,
        "schedule_cron": "0 2 * * *",
    }
    resp = client.post("/api/v1/accounts/connect", json=payload, headers=_auth(token))
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["schedule_id"] is not None
    schedule = db_session.get(Schedule, body["schedule_id"])
    assert schedule is not None
    assert schedule.cron == "0 2 * * *"


def test_connect_account_missing_name_rejected(client, db_session) -> None:
    token = _token(client, "admin")
    resp = client.post(
        "/api/v1/accounts/connect", json={"name": "", "method": "demo"}, headers=_auth(token)
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == "validation_error"


def test_connect_account_upload_with_no_files_rejected(client, db_session) -> None:
    token = _token(client, "admin")
    resp = client.post(
        "/api/v1/accounts/connect", json={"name": "Acme", "method": "upload"}, headers=_auth(token)
    )
    assert resp.status_code == 400


def test_connect_account_requires_admin(client, db_session) -> None:
    token = _token(client, "analyst")
    resp = client.post(
        "/api/v1/accounts/connect", json={"name": "Acme", "method": "demo"}, headers=_auth(token)
    )
    assert resp.status_code == 403


# ---- accounts: scan ----------------------------------------------------


def test_rescan_account(client, db_session, job_queue_spy) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    resp = client.post(f"/api/v1/accounts/{seeded['account_id']}/scan", headers=_auth(token))
    assert resp.status_code == 200
    run_id = resp.get_json()["run_id"]
    assert run_id != seeded["run_id"]
    _run_jobs(job_queue_spy)


def test_rescan_account_not_found(client, db_session) -> None:
    token = _token(client, "analyst")
    resp = client.post(f"/api/v1/accounts/{_BOGUS}/scan", headers=_auth(token))
    assert resp.status_code == 404


# ---- accounts: schedule CRUD ------------------------------------------------


def test_save_and_delete_schedule(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    resp = client.put(
        f"/api/v1/accounts/{seeded['account_id']}/schedule",
        json={"cron": "0 2 * * *", "enabled": True},
        headers=_auth(token),
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["cron"] == "0 2 * * *"
    assert body["enabled"] is True
    assert db_session.scalars(select(Schedule)).one().account_id == seeded["account_id"]

    resp2 = client.delete(f"/api/v1/accounts/{seeded['account_id']}/schedule", headers=_auth(token))
    assert resp2.status_code == 204
    assert db_session.scalars(select(Schedule)).first() is None


def test_save_schedule_invalid_cron_rejected(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    resp = client.put(
        f"/api/v1/accounts/{seeded['account_id']}/schedule",
        json={"cron": "not a cron", "enabled": True},
        headers=_auth(token),
    )
    assert resp.status_code == 400


def test_run_schedule_now(client, db_session, job_queue_spy) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    client.put(
        f"/api/v1/accounts/{seeded['account_id']}/schedule",
        json={"cron": "0 2 * * *", "enabled": True},
        headers=_auth(token),
    )
    resp = client.post(
        f"/api/v1/accounts/{seeded['account_id']}/schedule/run-now", headers=_auth(token)
    )
    assert resp.status_code == 200
    assert resp.get_json()["run_id"] is not None
    _run_jobs(job_queue_spy)


def test_run_schedule_now_without_a_schedule_404s(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    resp = client.post(
        f"/api/v1/accounts/{seeded['account_id']}/schedule/run-now", headers=_auth(token)
    )
    assert resp.status_code == 404


# ---- findings: transition ---------------------------------------------------


def test_transition_finding(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    resp = client.post(
        f"/api/v1/findings/{seeded['group_id']}/transition",
        json={"to_status": "investigating"},
        headers=_auth(token),
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["group"]["current_status"] == "investigating"
    assert body["activity"]


def test_invalid_transition_is_409(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    resp = client.post(
        f"/api/v1/findings/{seeded['group_id']}/transition",
        json={"to_status": "not_a_real_status"},
        headers=_auth(token),
    )
    assert resp.status_code == 409
    assert resp.get_json()["error"]["code"] == "invalid_transition"


def test_transition_not_found(client, db_session) -> None:
    token = _token(client, "analyst")
    resp = client.post(
        f"/api/v1/findings/{_BOGUS}/transition",
        json={"to_status": "investigating"},
        headers=_auth(token),
    )
    assert resp.status_code == 404


# ---- findings: suppress / accept-risk --------------------------------------


def test_suppress_is_analyst_but_accept_risk_is_admin(client, db_session) -> None:
    seeded = _seed(db_session)
    analyst_token = _token(client, "analyst")
    suppress = client.post(
        f"/api/v1/findings/{seeded['group_id']}/suppress",
        json={"reason": "known noise"},
        headers=_auth(analyst_token),
    )
    assert suppress.status_code == 200
    assert suppress.get_json()["group"]["current_status"] == "suppressed"

    admin_token = _token(client, "admin")
    accept = client.post(
        f"/api/v1/findings/{seeded['group_id']}/accept-risk",
        json={"reason": "tracked elsewhere"},
        headers=_auth(admin_token),
    )
    assert accept.status_code == 409  # already suppressed — not open anymore


def test_accept_risk_requires_admin(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    resp = client.post(
        f"/api/v1/findings/{seeded['group_id']}/accept-risk",
        json={"reason": "tracked elsewhere"},
        headers=_auth(token),
    )
    assert resp.status_code == 403


def test_suppress_empty_reason_rejected(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    resp = client.post(
        f"/api/v1/findings/{seeded['group_id']}/suppress",
        json={"reason": ""},
        headers=_auth(token),
    )
    assert resp.status_code == 400


def test_reopening_accepted_risk_via_transition_revokes_the_exception(client, db_session) -> None:
    """Mirrors ``test_authz.py``'s HTML-route version: reopening FROM an
    exception state must go through ``revoke_exception``, not a bare
    ``transition``, or the exception row would be left stale."""
    seeded = _seed(db_session)
    admin_token = _token(client, "admin")
    accept = client.post(
        f"/api/v1/findings/{seeded['group_id']}/accept-risk",
        json={"reason": "tracked elsewhere", "expires_at": "2099-01-01"},
        headers=_auth(admin_token),
    )
    assert accept.status_code == 200
    assert accept.get_json()["group"]["current_status"] == "accepted_risk"

    analyst_token = _token(client, "analyst")
    reopen = client.post(
        f"/api/v1/findings/{seeded['group_id']}/transition",
        json={"to_status": "open"},
        headers=_auth(analyst_token),
    )
    assert reopen.status_code == 200
    assert reopen.get_json()["group"]["current_status"] == "open"

    exc = db_session.scalars(select(FindingException)).one()
    assert exc.revoked_at is not None


# ---- findings: comment / assign --------------------------------------------


def test_comment(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    resp = client.post(
        f"/api/v1/findings/{seeded['group_id']}/comment",
        json={"body": "worth a look"},
        headers=_auth(token),
    )
    assert resp.status_code == 200
    bodies = [a["body"] for a in resp.get_json()["activity"] if a["body"]]
    assert "worth a look" in bodies


def test_comment_empty_body_rejected(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    resp = client.post(
        f"/api/v1/findings/{seeded['group_id']}/comment",
        json={"body": "   "},
        headers=_auth(token),
    )
    assert resp.status_code == 400


def test_assign_to_me_and_unassign(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    resp = client.post(
        f"/api/v1/findings/{seeded['group_id']}/assign",
        json={"assignee_id": "me"},
        headers=_auth(token),
    )
    assert resp.status_code == 200
    assert resp.get_json()["assignee_name"] == "Demo Analyst"

    resp2 = client.post(
        f"/api/v1/findings/{seeded['group_id']}/assign",
        json={"assignee_id": ""},
        headers=_auth(token),
    )
    assert resp2.status_code == 200
    assert resp2.get_json()["assignee_name"] is None


# ---- findings: bulk ----------------------------------------------------


def test_bulk_transition(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    resp = client.post(
        "/api/v1/findings/bulk/transition",
        json={"group_ids": [seeded["group_id"]], "to_status": "investigating"},
        headers=_auth(token),
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["action"] == "transition"
    assert body["succeeded"] == [seeded["group_id"]]
    assert body["count"] == 1
    assert body["failed"] == []


def test_bulk_transition_reports_failures_for_bogus_ids(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    resp = client.post(
        "/api/v1/findings/bulk/transition",
        json={"group_ids": [seeded["group_id"], _BOGUS], "to_status": "investigating"},
        headers=_auth(token),
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["succeeded"] == [seeded["group_id"]]
    assert body["failed"] == [{"group_id": _BOGUS, "reason": "not found"}]


def test_bulk_accept_risk_stays_admin_only_regardless_of_selection(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    resp = client.post(
        "/api/v1/findings/bulk/accept-risk",
        json={"group_ids": [seeded["group_id"]], "reason": "x"},
        headers=_auth(token),
    )
    assert resp.status_code == 403
    group = db_session.get(FindingGroup, seeded["group_id"])
    assert group.current_status == "open"  # nothing happened


def test_bulk_assign(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    resp = client.post(
        "/api/v1/findings/bulk/assign",
        json={"group_ids": [seeded["group_id"]], "assignee_id": "me"},
        headers=_auth(token),
    )
    assert resp.status_code == 200
    assert resp.get_json()["succeeded"] == [seeded["group_id"]]


def test_bulk_suppress(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    resp = client.post(
        "/api/v1/findings/bulk/suppress",
        json={"group_ids": [seeded["group_id"]], "reason": "batch noise"},
        headers=_auth(token),
    )
    assert resp.status_code == 200
    assert resp.get_json()["succeeded"] == [seeded["group_id"]]
    group = db_session.get(FindingGroup, seeded["group_id"])
    assert group.current_status == "suppressed"


# ---- findings: ticket (§7.5, Phase 4 Slice 5) -------------------------------


def test_create_ticket_via_api(client, db_session) -> None:
    from app.services.integration_service import create_target

    seeded = _seed(db_session)
    target = create_target(db_session, kind="jira", name="Jira", config={"project_key": "SEC"})
    db_session.commit()

    token = _token(client, "analyst")
    resp = client.post(
        f"/api/v1/findings/{seeded['group_id']}/ticket",
        json={"target_id": target.id, "title": "MFA gap", "body": "details"},
        headers=_auth(token),
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["group"]["ticket_ref"] is not None
    assert "(simulated)" in body["group"]["ticket_ref"]
    assert body["group"]["ticket_url"] is None


def test_create_ticket_unknown_target_is_400(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client, "analyst")
    resp = client.post(
        f"/api/v1/findings/{seeded['group_id']}/ticket",
        json={"target_id": _BOGUS, "title": "x", "body": ""},
        headers=_auth(token),
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == "validation_error"


def test_create_ticket_requires_admin_for_accept_risk_is_unaffected(client, db_session) -> None:
    """CREATE_TICKET is analyst-level, distinct from ACCEPT_RISK_CREATE —
    confirms the two capabilities weren't accidentally conflated."""
    from app.services.integration_service import create_target

    seeded = _seed(db_session)
    target = create_target(db_session, kind="webhook", name="Hook", config={"url": "https://x"})
    db_session.commit()

    token = _token(client, "analyst")
    resp = client.post(
        f"/api/v1/findings/{seeded['group_id']}/ticket",
        json={"target_id": target.id, "title": "x", "body": ""},
        headers=_auth(token),
    )
    # A real (unreachable) webhook URL — expect a 502 (integration_unreachable),
    # not a 403 — proving the role gate itself passed an analyst through.
    assert resp.status_code in (200, 502)


# ---- role matrix + unauthenticated -----------------------------------------
# (method, path, json_body, minimum_role) — bogus ids throughout; a
# non-403 downstream 404/409/400 is proof enough that the role gate let the
# caller through, same convention as test_authz.py's HTML-route matrix.


def _matrix() -> list[tuple[str, str, dict, str]]:
    return [
        ("POST", "/api/v1/accounts/connect", {"name": "", "method": "demo"}, "admin"),
        ("POST", f"/api/v1/accounts/{_BOGUS}/scan", {}, "analyst"),
        ("PUT", f"/api/v1/accounts/{_BOGUS}/schedule", {"cron": "0 2 * * *"}, "analyst"),
        ("DELETE", f"/api/v1/accounts/{_BOGUS}/schedule", {}, "analyst"),
        ("POST", f"/api/v1/accounts/{_BOGUS}/schedule/run-now", {}, "analyst"),
        (
            "POST",
            f"/api/v1/findings/{_BOGUS}/transition",
            {"to_status": "investigating"},
            "analyst",
        ),
        ("POST", f"/api/v1/findings/{_BOGUS}/suppress", {"reason": "x"}, "analyst"),
        ("POST", f"/api/v1/findings/{_BOGUS}/accept-risk", {"reason": "x"}, "admin"),
        ("POST", f"/api/v1/findings/{_BOGUS}/comment", {"body": "x"}, "analyst"),
        ("POST", f"/api/v1/findings/{_BOGUS}/assign", {"assignee_id": "me"}, "analyst"),
        (
            "POST",
            "/api/v1/findings/bulk/transition",
            {"group_ids": [], "to_status": "investigating"},
            "analyst",
        ),
        ("POST", "/api/v1/findings/bulk/assign", {"group_ids": [], "assignee_id": "me"}, "analyst"),
        ("POST", "/api/v1/findings/bulk/suppress", {"group_ids": [], "reason": "x"}, "analyst"),
        ("POST", "/api/v1/findings/bulk/accept-risk", {"group_ids": [], "reason": "x"}, "admin"),
        (
            "POST",
            f"/api/v1/findings/{_BOGUS}/ticket",
            {"target_id": 1, "title": "x", "body": "x"},
            "analyst",
        ),
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
]


@pytest.mark.parametrize("role", _ROLES)
@pytest.mark.parametrize(("idx",), [(i,) for i in range(len(_MATRIX_IDS))], ids=_MATRIX_IDS)
def test_route_x_role_matrix(client, db_session, role, idx) -> None:
    method, path, body, minimum = _matrix()[idx]
    token = _token(client, role)
    resp = client.open(path, method=method, json=body, headers=_auth(token))

    allowed = _ROLES.index(role) >= _ROLES.index(minimum)
    if allowed:
        assert resp.status_code != 403, f"{role} (>= {minimum}) was blocked from {method} {path}"
    else:
        assert resp.status_code == 403, f"{role} (< {minimum}) was NOT blocked from {method} {path}"


@pytest.mark.parametrize(("idx",), [(i,) for i in range(len(_MATRIX_IDS))], ids=_MATRIX_IDS)
def test_unauthenticated_caller_blocked_from_every_mutating_route(client, db_session, idx) -> None:
    method, path, body, _minimum = _matrix()[idx]
    resp = client.open(path, method=method, json=body)
    assert resp.status_code == 401
