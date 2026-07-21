"""Read-surface endpoint tests for /api/v1 (§10.4, Phase 4 Slice 4a) — every
GET against real seeded scan data, reusing the exact same file-adapter sample
data as the rest of the integration suite. Covers pagination/X-Total-Count,
404s, the ``?account_id=``/``?run_id=`` overrides, and that all three roles
(VIEW = read_only) can reach every route while an unauthenticated caller
cannot — the "same capability matrix as the HTML app" requirement, made
concrete for a surface where every listed route happens to be VIEW-level.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from app.models import FindingGroup
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
    principal_uid = db_session.scalars(
        select(FindingGroup.principal_uid).where(FindingGroup.principal_uid.is_not(None))
    ).first()
    assert group_id is not None and principal_uid is not None
    return {
        "account_id": account.id,
        "run_id": run.id,
        "group_id": group_id,
        "principal_uid": principal_uid,
    }


# ---- /me --------------------------------------------------------------------


def test_me(client, db_session) -> None:
    token = _token(client)
    resp = client.get("/api/v1/me", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["email"] == "admin@example.com"
    assert body["role"] == "admin"


# ---- /accounts ----------------------------------------------------------


def test_list_accounts(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client)
    resp = client.get("/api/v1/accounts", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.headers["X-Total-Count"] == "1"
    body = resp.get_json()
    assert body[0]["account"]["id"] == seeded["account_id"]
    assert body[0]["account"]["name"] == "Acme Corp"
    assert body[0]["total_findings"] == 31


def test_accounts_pagination(client, db_session) -> None:
    _seed(db_session)
    token = _token(client)
    resp = client.get("/api/v1/accounts?limit=0", headers=_auth(token))
    assert resp.status_code == 422  # limit below the schema's min=1

    resp = client.get("/api/v1/accounts?limit=1&offset=5", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.get_json() == []
    assert resp.headers["X-Total-Count"] == "1"  # total reflects all rows, not the page


# ---- /runs ----------------------------------------------------------------


def test_list_runs(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client)
    resp = client.get("/api/v1/runs", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.headers["X-Total-Count"] == "1"
    assert resp.get_json()[0]["run"]["id"] == seeded["run_id"]


def test_get_run(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client)
    resp = client.get(f"/api/v1/runs/{seeded['run_id']}", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.get_json()["run"]["status"] == "completed"


def test_get_run_not_found(client, db_session) -> None:
    token = _token(client)
    resp = client.get("/api/v1/runs/999999", headers=_auth(token))
    assert resp.status_code == 404
    assert resp.get_json()["error"]["code"] == "not_found"


def test_get_run_findings(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client)
    resp = client.get(f"/api/v1/runs/{seeded['run_id']}/findings", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.headers["X-Total-Count"] == "31"
    assert len(resp.get_json()) == 31


def test_get_run_findings_paginated(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client)
    resp = client.get(
        f"/api/v1/runs/{seeded['run_id']}/findings?limit=5&offset=10", headers=_auth(token)
    )
    assert resp.status_code == 200
    assert len(resp.get_json()) == 5
    assert resp.headers["X-Total-Count"] == "31"


def test_get_run_findings_not_found(client, db_session) -> None:
    token = _token(client)
    resp = client.get("/api/v1/runs/999999/findings", headers=_auth(token))
    assert resp.status_code == 404


def test_run_report_json_matches_export_service(client, db_session) -> None:
    from app.services.export_service import run_to_json

    seeded = _seed(db_session)
    token = _token(client)
    resp = client.get(f"/api/v1/runs/{seeded['run_id']}/report.json", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.content_type == "application/json"
    expected = run_to_json(db_session, seeded["run_id"])
    assert resp.get_json() == __import__("json").loads(expected)


def test_run_report_csv(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client)
    resp = client.get(f"/api/v1/runs/{seeded['run_id']}/report.csv", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.content_type.startswith("text/csv")
    assert resp.get_data(as_text=True).startswith("check_id,")


def test_run_report_not_found(client, db_session) -> None:
    token = _token(client)
    assert client.get("/api/v1/runs/999999/report.json", headers=_auth(token)).status_code == 404
    assert client.get("/api/v1/runs/999999/report.csv", headers=_auth(token)).status_code == 404


# ---- /findings --------------------------------------------------------------


def test_list_findings_defaults_to_current_account(client, db_session) -> None:
    _seed(db_session)
    token = _token(client)
    resp = client.get("/api/v1/findings", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.headers["X-Total-Count"] == "31"


def test_list_findings_filters_by_severity(client, db_session) -> None:
    _seed(db_session)
    token = _token(client)
    resp = client.get("/api/v1/findings?severity=CRITICAL", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body
    assert all(f["severity"] == "CRITICAL" for f in body)


def test_list_findings_explicit_account_id(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client)
    resp = client.get(f"/api/v1/findings?account_id={seeded['account_id']}", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.headers["X-Total-Count"] == "31"


def test_get_finding_detail(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client)
    resp = client.get(f"/api/v1/findings/{seeded['group_id']}", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["group"]["id"] == seeded["group_id"]
    assert body["finding"]["group_id"] == seeded["group_id"]
    assert isinstance(body["actions"], list)
    assert body["activity"]


def test_get_finding_detail_not_found(client, db_session) -> None:
    token = _token(client)
    resp = client.get("/api/v1/findings/999999", headers=_auth(token))
    assert resp.status_code == 404


def test_get_finding_detail_actions_are_role_filtered(client, db_session) -> None:
    """Mirrors the HTML drawer's role filtering (§10.2) — a viewer sees no
    status actions on a finding the same way they see none in the HTML app."""
    seeded = _seed(db_session)
    viewer_token = _token(client, "read_only")
    resp = client.get(f"/api/v1/findings/{seeded['group_id']}", headers=_auth(viewer_token))
    assert resp.status_code == 200
    assert resp.get_json()["actions"] == []

    admin_token = _token(client, "admin")
    resp2 = client.get(f"/api/v1/findings/{seeded['group_id']}", headers=_auth(admin_token))
    assert resp2.get_json()["actions"]  # non-empty for admin


# ---- /principals --------------------------------------------------------


def test_list_principals(client, db_session) -> None:
    _seed(db_session)
    token = _token(client)
    resp = client.get("/api/v1/principals", headers=_auth(token))
    assert resp.status_code == 200
    assert int(resp.headers["X-Total-Count"]) > 0
    assert resp.get_json()


def test_get_principal_graph(client, db_session) -> None:
    seeded = _seed(db_session)
    token = _token(client)
    resp = client.get(f"/api/v1/principals/{seeded['principal_uid']}/graph", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["focus"] == seeded["principal_uid"]
    assert "nodes" in body and "edges" in body


def test_get_principal_graph_not_found(client, db_session) -> None:
    _seed(db_session)  # a completed run must exist so this 404 is genuinely "no such principal"
    token = _token(client)
    resp = client.get("/api/v1/principals/does-not-exist/graph", headers=_auth(token))
    assert resp.status_code == 404


def test_principal_graph_uid_with_slashes(client, db_session) -> None:
    """principal_uid values look like 'user/intern' — the path converter
    must accept the embedded slash."""
    seeded = _seed(db_session)
    assert "/" in seeded["principal_uid"]
    token = _token(client)
    resp = client.get(f"/api/v1/principals/{seeded['principal_uid']}/graph", headers=_auth(token))
    assert resp.status_code == 200


# ---- /compliance / /checks --------------------------------------------------


def test_list_compliance(client, db_session) -> None:
    _seed(db_session)
    token = _token(client)
    resp = client.get("/api/v1/compliance", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.headers["X-Total-Count"] == "3"  # CIS/SOC2/NIST
    assert {f["key"] for f in resp.get_json()} == {"CIS_AWS_1.4", "SOC2", "NIST"}


def test_list_checks_works_pre_scan(client, db_session) -> None:
    """The catalog renders even with no run yet (checks_catalog's own
    documented behavior) — verify the API surface preserves that."""
    token = _token(client)
    resp = client.get("/api/v1/checks", headers=_auth(token))
    assert resp.status_code == 200
    assert int(resp.headers["X-Total-Count"]) >= 20
    assert all(row["finding_count"] == 0 for row in resp.get_json())


def test_list_checks_after_scan_has_finding_counts(client, db_session) -> None:
    _seed(db_session)
    token = _token(client)
    resp = client.get("/api/v1/checks", headers=_auth(token))
    assert resp.status_code == 200
    assert any(row["finding_count"] > 0 for row in resp.get_json())


# ---- role matrix: every route is VIEW-level, reachable by all 3 roles -----


_ALL_GET_PATHS = [
    "/api/v1/me",
    "/api/v1/accounts",
    "/api/v1/runs",
    "/api/v1/findings",
    "/api/v1/principals",
    "/api/v1/compliance",
    "/api/v1/checks",
]


@pytest.mark.parametrize("role", ["admin", "analyst", "read_only"])
def test_every_role_can_reach_every_list_route(client, db_session, role) -> None:
    _seed(db_session)
    token = _token(client, role)
    for path in _ALL_GET_PATHS:
        resp = client.get(path, headers=_auth(token))
        assert resp.status_code == 200, f"{role} was blocked from {path}"


@pytest.mark.parametrize("path", _ALL_GET_PATHS)
def test_unauthenticated_caller_blocked_from_every_route(client, db_session, path) -> None:
    resp = client.get(path)
    assert resp.status_code == 401
