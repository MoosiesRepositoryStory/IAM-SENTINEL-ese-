"""Blast Radius UI support (§6.2 rendering, Phase 3 Slice 2).

Shapes the ``PermissionEdge`` rows a scan already persisted (Slice 1) into
Cytoscape.js elements for one principal's neighborhood, and lists principals
for the overview page. Read-only query support, same shape as
``run_query.py``/``account_service.py`` — dataclasses/dicts the view can use
after the session closes, no lazy-loaded relationship access.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding, PermissionEdge, Policy, Principal

# Edge relations followed when expanding a principal/role's own "why can it do
# that" policy chain (§6.2's HAS_POLICY -> GRANTS_ACTION -> ON_RESOURCE nodes).
_POLICY_CHAIN_RELATIONS = {"HAS_POLICY", "GRANTS_ACTION", "ON_RESOURCE"}
# Relations that move between two *principal* nodes — a hop worth following
# out from the focal principal, but not recursed on further (that would pull
# in unrelated parts of the account graph rather than this principal's own
# blast radius).
_PRINCIPAL_HOP_RELATIONS = {"CAN_ASSUME", "CAN_ESCALATE"}


@dataclass
class PrincipalBlastRow:
    principal_uid: str
    username: str | None
    kind: str
    blast_radius_score: int
    reachable_actions: int
    reachable_sensitive: int


def list_principals_by_blast(session: Session, run_id: int) -> list[PrincipalBlastRow]:
    """All principals for a run, riskiest first — the Blast Radius overview page."""
    rows = session.scalars(
        select(Principal)
        .where(Principal.run_id == run_id)
        .order_by(Principal.blast_radius_score.desc().nulls_last(), Principal.principal_uid)
    ).all()
    return [
        PrincipalBlastRow(
            principal_uid=p.principal_uid,
            username=p.username,
            kind=p.kind,
            blast_radius_score=p.blast_radius_score or 0,
            reachable_actions=p.reachable_actions or 0,
            reachable_sensitive=p.reachable_sensitive or 0,
        )
        for p in rows
    ]


def _node_id(node_type: str, uid: str) -> str:
    return f"{node_type}:{uid}"


def _short_label(uid: str) -> str:
    """Trim a long ARN/inline-policy id down to its trailing segment for the
    graph label; the full id stays available as a tooltip/side-panel field."""
    for sep in ("/", ":"):
        if sep in uid:
            return uid.rsplit(sep, 1)[-1]
    return uid


def _escalation_path(session: Session, run_id: int, principal_uid: str) -> list[str] | None:
    """The stored graph path from this principal to an admin-equivalent node,
    if the escalation check found and recorded one for it (Slice 1)."""
    finding = session.scalar(
        select(Finding).where(
            Finding.run_id == run_id,
            Finding.principal_uid == principal_uid,
            Finding.check_id == "iam.escalation.passrole_createkey",
        )
    )
    if finding is None:
        return None
    path = finding.evidence.get("graph_path")
    return list(path) if isinstance(path, list) and len(path) > 1 else None


def principal_graph(session: Session, run_id: int, principal_uid: str) -> dict[str, Any] | None:
    """Cytoscape elements for ``principal_uid``'s own blast-radius neighborhood.

    Scope (kept deliberately small — this is one principal's story, not the
    whole account graph): the principal's own policy chain, its direct
    CAN_ASSUME/CAN_ESCALATE targets, and *those* targets' own policy chains
    (so "why is bob dangerous" is visible without pulling in bob's own
    further escalation targets, which would be a different principal's page).
    """
    principal = session.scalar(
        select(Principal).where(Principal.run_id == run_id, Principal.principal_uid == principal_uid)
    )
    if principal is None:
        return None

    principals_by_uid = {
        p.principal_uid: p
        for p in session.scalars(select(Principal).where(Principal.run_id == run_id)).all()
    }
    policy_names = {
        p.policy_uid: p.name
        for p in session.scalars(select(Policy).where(Policy.run_id == run_id)).all()
    }
    edges = session.scalars(select(PermissionEdge).where(PermissionEdge.run_id == run_id)).all()
    by_src: dict[str, list[PermissionEdge]] = {}
    for e in edges:
        by_src.setdefault(e.src_uid, []).append(e)

    escalation_path = _escalation_path(session, run_id, principal_uid)
    on_path_pairs = (
        set(zip(escalation_path, escalation_path[1:], strict=False)) if escalation_path else set()
    )

    nodes: dict[str, dict[str, Any]] = {}
    cy_edges: dict[str, dict[str, Any]] = {}

    def add_node(node_type: str, uid: str) -> None:
        node_id = _node_id(node_type, uid)
        if node_id in nodes:
            return
        data: dict[str, Any] = {
            "id": node_id, "type": node_type, "uid": uid,
            "label": _short_label(uid), "is_focus": uid == principal_uid,
        }
        if node_type == "principal":
            p = principals_by_uid.get(uid)
            if p is not None:
                data["label"] = p.username or _short_label(uid)
                data["kind"] = p.kind
                data["blast_radius_score"] = p.blast_radius_score or 0
                data["reachable_actions"] = p.reachable_actions or 0
                data["reachable_sensitive"] = p.reachable_sensitive or 0
        elif node_type == "policy":
            data["label"] = policy_names.get(uid, _short_label(uid))
        nodes[node_id] = {"data": data}

    def add_edge(e: PermissionEdge) -> None:
        key = f"{e.src_type}:{e.src_uid}->{e.dst_type}:{e.dst_uid}:{e.relation}"
        if key in cy_edges:
            return
        add_node(e.src_type, e.src_uid)
        add_node(e.dst_type, e.dst_uid)
        cy_edges[key] = {
            "data": {
                "id": key,
                "source": _node_id(e.src_type, e.src_uid),
                "target": _node_id(e.dst_type, e.dst_uid),
                "relation": e.relation,
                "sensitive": e.is_sensitive,
                "on_path": (e.src_uid, e.dst_uid) in on_path_pairs,
            }
        }

    def add_policy_chain(start_uid: str) -> None:
        """Walk principal -HAS_POLICY-> policy -GRANTS_ACTION-> action
        -ON_RESOURCE-> resource transitively — each hop's edges are keyed by
        *that hop's own* src_uid (e.g. the policy's, not the principal's), so
        this has to walk the chain rather than filter one uid's own edges."""
        frontier = [start_uid]
        seen = {start_uid}
        while frontier:
            uid = frontier.pop()
            for e in by_src.get(uid, []):
                if e.relation not in _POLICY_CHAIN_RELATIONS:
                    continue
                add_edge(e)
                if e.dst_uid not in seen:
                    seen.add(e.dst_uid)
                    frontier.append(e.dst_uid)

    add_node("principal", principal_uid)
    add_policy_chain(principal_uid)

    hop_targets: list[str] = []
    for e in by_src.get(principal_uid, []):
        if e.relation in _PRINCIPAL_HOP_RELATIONS:
            add_edge(e)
            hop_targets.append(e.dst_uid)

    # A principal like intern can CAN_ESCALATE to *every* other user (anyone
    # whose credentials it could mint) — drawing every one of their full
    # policy chains buries the one story this page exists to tell in noise.
    # When there's a recorded escalation path, expand only the uids actually
    # on it; otherwise (no headline path — e.g. viewing bob himself) expand
    # every direct hop target, which in practice is a small, informative set.
    expand_uids = set(escalation_path[1:]) if escalation_path else set(hop_targets)
    for uid in hop_targets:
        if uid in expand_uids:
            add_policy_chain(uid)

    return {
        "focus": principal_uid,
        "focus_label": principal.username or _short_label(principal_uid),
        "nodes": list(nodes.values()),
        "edges": list(cy_edges.values()),
        "escalation_path": escalation_path,
    }
