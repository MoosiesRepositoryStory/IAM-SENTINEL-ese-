"""Blast Radius UI data-serialization tests (§6.2 rendering, Phase 3 Slice 2).

Runs against a real moto scan (not a mocked graph, per the same "the demo
org is the marquee default" posture as the rest of Phase 2/3) so the
intern -> bob escalation story used to verify the Cytoscape rendering is
exercised here too, not just eyeballed in a browser.
"""

from __future__ import annotations

import pytest

pytest.importorskip("boto3")
pytest.importorskip("moto")

from app.services import create_account, run_scan  # noqa: E402
from app.services.graph_view import list_principals_by_blast, principal_graph  # noqa: E402

pytestmark = pytest.mark.integration


def _scan(db_session) -> tuple[int, int]:  # noqa: ANN001
    account = create_account(db_session, name="Acme (moto)", source_type="moto_aws")
    run = run_scan(db_session, account.id)
    return account.id, run.id


def _uid(session, run_id: int, username: str) -> str:  # noqa: ANN001
    from app.models import Principal
    from sqlalchemy import select

    return session.scalar(
        select(Principal.principal_uid).where(
            Principal.run_id == run_id, Principal.username == username
        )
    )


def test_list_principals_by_blast_sorted_desc(db_session) -> None:
    _, run_id = _scan(db_session)
    rows = list_principals_by_blast(db_session, run_id)
    assert len(rows) == 16  # 10 users + 6 roles
    scores = [r.blast_radius_score for r in rows]
    assert scores == sorted(scores, reverse=True)
    intern = next(r for r in rows if r.username == "intern")
    assert intern.blast_radius_score > 0


def test_unknown_principal_returns_none(db_session) -> None:
    _, run_id = _scan(db_session)
    assert principal_graph(db_session, run_id, "not-a-real-uid") is None


def test_intern_graph_shows_the_escalation_path_to_bob(db_session) -> None:
    _, run_id = _scan(db_session)
    intern_uid = _uid(db_session, run_id, "intern")
    bob_uid = _uid(db_session, run_id, "bob")

    graph = principal_graph(db_session, run_id, intern_uid)
    assert graph is not None
    assert graph["focus"] == intern_uid
    assert graph["focus_label"] == "intern"
    assert graph["escalation_path"] == [intern_uid, bob_uid]

    node_ids = {n["data"]["id"] for n in graph["nodes"]}
    assert f"principal:{intern_uid}" in node_ids
    assert f"principal:{bob_uid}" in node_ids

    focus_node = next(n["data"] for n in graph["nodes"] if n["data"]["id"] == f"principal:{intern_uid}")
    assert focus_node["is_focus"] is True
    assert focus_node["blast_radius_score"] > 0

    # Policy/action nodes are present (intern's own inline escalation policy)
    # with a real name, not just a raw uid dumped as the label.
    assert any(n["data"]["type"] == "policy" for n in graph["nodes"])
    assert any(n["data"]["type"] == "action" for n in graph["nodes"])

    escalate_edges = [e["data"] for e in graph["edges"] if e["data"]["relation"] == "CAN_ESCALATE"]
    assert escalate_edges, "expected at least one CAN_ESCALATE edge out of intern"
    on_path_edges = [
        e["data"]
        for e in graph["edges"]
        if e["data"]["source"] == f"principal:{intern_uid}"
        and e["data"]["target"] == f"principal:{bob_uid}"
    ]
    assert on_path_edges and on_path_edges[0]["on_path"] is True


def test_isolated_principal_graph_is_just_the_focus_node(db_session) -> None:
    """dormant has no policies/logins/edges at all — still a valid graph."""
    _, run_id = _scan(db_session)
    dormant_uid = _uid(db_session, run_id, "dormant")
    graph = principal_graph(db_session, run_id, dormant_uid)
    assert graph is not None
    assert graph["edges"] == []
    assert [n["data"]["id"] for n in graph["nodes"]] == [f"principal:{dormant_uid}"]
    assert graph["escalation_path"] is None


def test_policy_node_label_uses_real_policy_name_not_raw_uid(db_session) -> None:
    _, run_id = _scan(db_session)
    bob_uid = _uid(db_session, run_id, "bob")
    graph = principal_graph(db_session, run_id, bob_uid)
    assert graph is not None
    policy_nodes = [n["data"] for n in graph["nodes"] if n["data"]["type"] == "policy"]
    assert any(n["label"] == "AdminAccess" for n in policy_nodes)
