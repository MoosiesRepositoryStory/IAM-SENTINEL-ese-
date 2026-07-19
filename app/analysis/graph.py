"""Permission graph & blast-radius model (§6.2, Phase 3 Slice 1).

Builds a directed graph over principals, policies, actions, and resources from
an ingested :class:`NormalizedDataset`, then derives two things from it:

- **Blast radius** per principal (§6.2 steps 1-4), written back onto each
  :class:`PrincipalRecord` in place so ``risk.py``'s impact scoring — which
  already reads ``principal.blast_radius_score`` — sees real numbers instead
  of the Phase-0 placeholder default of 0.
- **Escalation paths**: ``CAN_ESCALATE``/``CAN_ASSUME`` chains that reach an
  admin-equivalent node, keyed by the principal they start from, for the
  existing ``iam.escalation.passrole_createkey`` check to attach as evidence
  and for the Slice 2 graph view to render.

Deliberately not a full IAM policy evaluation engine (§15.1): edges are
derived from a curated set of structural signals (attached policies, trust
policy ``Principal`` fields, a short list of escalation-primitive actions),
not condition-key or resource-policy-intersection evaluation. ``networkx`` is
an optional dependency (the ``graph`` extra, also installed in ``dev`` per
the same "CI actually exercises this" reasoning as boto3/moto/APScheduler) —
when it isn't installed, :func:`build` degrades gracefully to an empty graph
rather than failing the scan, the same posture ``app.ingestion`` takes for
the cloud extra.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib.util import find_spec
from typing import TYPE_CHECKING, Any

from app.domain import policy as pol
from app.domain.records import NormalizedDataset, PolicyRecord, PrincipalRecord

if TYPE_CHECKING:
    import networkx as nx

_HAS_NETWORKX = find_spec("networkx") is not None

# Actions that, paired with iam:PassRole, let a principal act as any role it
# can pass to a compute service it controls.
_COMPUTE_LAUNCH_ACTIONS = ("ec2:RunInstances", "lambda:CreateFunction")
# Actions that let a principal mint or change credentials for *another*
# principal.
_CREATE_CREDENTIAL_ACTIONS = (
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
)
# Actions that let a principal attach an arbitrary (including admin) policy
# to itself.
_SELF_ATTACH_ACTIONS = (
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
)

# Blast-radius formula caps/weights (§6.2 step 4) — verbatim from the spec.
_SENSITIVE_CAP = 25
_ACTIONS_CAP = 300
_ROLES_CAP = 10
_W_SENSITIVE = 0.45
_W_ACTIONS = 0.25
_W_ADMIN = 0.20
_W_ROLES = 0.10


@dataclass
class GraphEdge:
    """Mirrors a ``PermissionEdge`` row; the scan pipeline persists these."""

    src_type: str
    src_uid: str
    dst_type: str
    dst_uid: str
    relation: str
    effect: str | None = None
    is_sensitive: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EscalationPath:
    """A concrete escalation chain from ``principal_uid`` to an admin-equivalent node."""

    principal_uid: str
    hops: list[str]
    via: str
    target_uid: str


@dataclass
class GraphResult:
    edges: list[GraphEdge] = field(default_factory=list)
    escalations: dict[str, list[EscalationPath]] = field(default_factory=dict)


def _node(kind: str, uid: str) -> str:
    return f"{kind}:{uid}"


def _principal_granted_actions(dataset: NormalizedDataset, p: PrincipalRecord) -> set[str]:
    actions: set[str] = set()
    for policy in dataset.policies_for(p):
        actions |= policy.granted_actions
    return actions


def build(dataset: NormalizedDataset) -> GraphResult:
    """Build the permission graph and populate blast-radius fields in place.

    Mutates ``blast_radius_score`` / ``reachable_actions`` / ``reachable_sensitive``
    on every principal in ``dataset`` and returns the derived edges + escalation
    paths for persistence and evidence enrichment.
    """
    if not _HAS_NETWORKX or not dataset.principals:
        return GraphResult()

    import networkx as nx

    g: nx.DiGraph = nx.DiGraph()
    edges: list[GraphEdge] = []
    seen_edges: set[tuple[str, str, str]] = set()

    def add_edge(e: GraphEdge) -> None:
        key = (_node(e.src_type, e.src_uid), _node(e.dst_type, e.dst_uid), e.relation)
        if key in seen_edges:
            return
        seen_edges.add(key)
        edges.append(e)
        g.add_edge(
            key[0], key[1], relation=e.relation, sensitive=e.is_sensitive, via=e.metadata.get("via")
        )

    principal_uids = {p.principal_uid for p in dataset.principals}
    for p in dataset.principals:
        g.add_node(_node("principal", p.principal_uid), kind=p.kind)

    _add_policy_edges(dataset, add_edge)
    _add_assume_edges(dataset, principal_uids, add_edge)
    self_attach_via = _add_escalation_edges(dataset, add_edge)

    granted_by_principal = {
        p.principal_uid: _principal_granted_actions(dataset, p) for p in dataset.principals
    }
    direct_admin_nodes = {
        _node("principal", uid) for uid, actions in granted_by_principal.items() if "*" in actions
    }
    # A self-attach primitive makes a principal admin-equivalent on its own —
    # it doesn't need another already-admin principal to reach.
    self_escalating = {_node("principal", uid): via for uid, via in self_attach_via.items()}
    admin_nodes = direct_admin_nodes | set(self_escalating)

    escalations: dict[str, list[EscalationPath]] = {}
    for p in dataset.principals:
        _score_principal(
            g,
            p,
            direct_admin_nodes,
            admin_nodes,
            self_escalating,
            granted_by_principal,
            escalations,
        )

    return GraphResult(edges=edges, escalations=escalations)


def _add_policy_edges(dataset: NormalizedDataset, add_edge: Any) -> None:
    """``principal -HAS_POLICY-> policy -GRANTS_ACTION-> action -ON_RESOURCE-> resource``."""
    policies = dataset.policy_by_uid()
    for p in dataset.principals:
        for policy_uid in p.attached_policy_uids:
            policy = policies.get(policy_uid)
            if policy is None:
                continue
            add_edge(GraphEdge("principal", p.principal_uid, "policy", policy_uid, "HAS_POLICY"))
            _add_statement_edges(policy, add_edge)


def _add_statement_edges(policy: PolicyRecord, add_edge: Any) -> None:
    for st in pol.statements(policy.document):
        if not pol.is_allow(st):
            continue
        actions = pol.actions(st) or (["*"] if pol.not_actions(st) else [])
        resources = pol.resources(st) or ["*"]
        for action in actions:
            add_edge(
                GraphEdge(
                    "policy",
                    policy.policy_uid,
                    "action",
                    action,
                    "GRANTS_ACTION",
                    is_sensitive=pol.is_sensitive_action(action, pol.SENSITIVE_ACTIONS),
                )
            )
            for resource in resources:
                add_edge(GraphEdge("action", action, "resource", resource, "ON_RESOURCE"))


def _trust_principal_arns(principal_field: Any) -> list[str]:
    """Extract candidate ``Principal.AWS`` ARNs a trust statement names.

    ``Principal: "*"`` (public) and ``{"Service": ...}`` (an AWS service, not
    a principal in this dataset) are deliberately not resolved to ARNs here —
    the wildcard case is already its own CRITICAL finding
    (``iam.role.trust_wildcard_principal``); fanning it out to every
    principal in the account would overstate blast radius for something
    that's actually "any account, not just this one's users."
    """
    if not isinstance(principal_field, dict):
        return []
    aws = principal_field.get("AWS")
    if aws is None:
        return []
    return [aws] if isinstance(aws, str) else [a for a in aws if isinstance(a, str)]


def _add_assume_edges(dataset: NormalizedDataset, principal_uids: set[str], add_edge: Any) -> None:
    """``principal -CAN_ASSUME-> role``, from trust policies naming a known principal ARN."""
    for p in dataset.principals:
        if p.kind != "role":
            continue
        trust = p.raw.get("trust_policy") or p.raw.get("AssumeRolePolicyDocument")
        if not isinstance(trust, dict):
            continue
        for st in pol.statements(trust):
            if not pol.is_assume_role_statement(st):
                continue
            for arn in _trust_principal_arns(st.get("Principal")):
                if arn in principal_uids and arn != p.principal_uid:
                    add_edge(
                        GraphEdge(
                            "principal",
                            arn,
                            "principal",
                            p.principal_uid,
                            "CAN_ASSUME",
                            is_sensitive=True,
                        )
                    )


def _add_escalation_edges(dataset: NormalizedDataset, add_edge: Any) -> dict[str, str]:
    """``principal -CAN_ESCALATE-> principal/role``, from the three §6.2 primitives.

    Returns ``{principal_uid: action}`` for principals matching the
    self-attach primitive — those are admin-equivalent on their own (they can
    attach any policy, including an admin one, to themselves) independent of
    whether another principal in the dataset already holds admin, which the
    generic graph-reachability walk in :func:`_score_principal` can't see on
    its own since nothing distinguishes "attaches to self" from "attaches to
    anyone" once it's just an edge back to the same node.
    """
    roles = [p for p in dataset.principals if p.kind == "role"]
    users = [p for p in dataset.principals if p.kind != "role"]
    self_attach_via: dict[str, str] = {}

    for p in dataset.principals:
        actions = _principal_granted_actions(dataset, p)
        if not actions:
            continue

        if pol.grants_action(actions, "iam:PassRole") and any(
            pol.grants_action(actions, a) for a in _COMPUTE_LAUNCH_ACTIONS
        ):
            for role in roles:
                if role.principal_uid != p.principal_uid:
                    add_edge(
                        GraphEdge(
                            "principal",
                            p.principal_uid,
                            "principal",
                            role.principal_uid,
                            "CAN_ESCALATE",
                            is_sensitive=True,
                            metadata={"via": "passrole_compute_launch"},
                        )
                    )

        if any(pol.grants_action(actions, a) for a in _CREATE_CREDENTIAL_ACTIONS):
            via = next(a for a in _CREATE_CREDENTIAL_ACTIONS if pol.grants_action(actions, a))
            for other in users:
                if other.principal_uid != p.principal_uid:
                    add_edge(
                        GraphEdge(
                            "principal",
                            p.principal_uid,
                            "principal",
                            other.principal_uid,
                            "CAN_ESCALATE",
                            is_sensitive=True,
                            metadata={"via": via},
                        )
                    )

        if any(pol.grants_action(actions, a) for a in _SELF_ATTACH_ACTIONS):
            via = next(a for a in _SELF_ATTACH_ACTIONS if pol.grants_action(actions, a))
            self_attach_via[p.principal_uid] = via
            add_edge(
                GraphEdge(
                    "principal",
                    p.principal_uid,
                    "principal",
                    p.principal_uid,
                    "CAN_ESCALATE",
                    is_sensitive=True,
                    metadata={"via": via},
                )
            )

    return self_attach_via


def _shortest_of(escalation_graph: nx.DiGraph, source: str, targets: list[str]) -> list[str] | None:
    """Shortest hop path from ``source`` to whichever of ``targets`` is closest.

    ``targets`` is pre-sorted by uid, so equal-length candidates resolve to a
    deterministic (alphabetically-first) choice — e.g. preferring "bob" over
    "frank" when both admins are equally reachable, rather than depending on
    dict/set iteration order.
    """
    import networkx as nx

    best: list[str] | None = None
    for target in targets:
        try:
            path = nx.shortest_path(escalation_graph, source, target)
        except nx.NetworkXNoPath:
            continue
        if best is None or len(path) < len(best):
            best = path
    return best


def _score_principal(
    g: nx.DiGraph,
    p: PrincipalRecord,
    direct_admin_nodes: set[str],
    admin_nodes: set[str],
    self_escalating: dict[str, str],
    granted_by_principal: dict[str, set[str]],
    escalations: dict[str, list[EscalationPath]],
) -> None:
    import networkx as nx

    self_node = _node("principal", p.principal_uid)

    # Step 1: transitive closure of CAN_ASSUME only — "assumable roles."
    assume_only = nx.DiGraph(
        (u, v) for u, v, d in g.edges(data=True) if d.get("relation") == "CAN_ASSUME"
    )
    assumable = nx.descendants(assume_only, self_node) if self_node in assume_only else set()
    assumable_role_uids = {n.split(":", 1)[1] for n in assumable}

    # Step 2: union of granted actions across the principal + every assumable role.
    union_actions = set(granted_by_principal.get(p.principal_uid, set()))
    for uid in assumable_role_uids:
        union_actions |= granted_by_principal.get(uid, set())

    # Step 3.
    reachable_actions = len(union_actions)
    reachable_sensitive = sum(
        1 for a in union_actions if pol.is_sensitive_action(a, pol.SENSITIVE_ACTIONS)
    )

    # can_reach_admin: via direct grants, an assumable role, or an escalation
    # chain (CAN_ASSUME + CAN_ESCALATE together) reaching an admin-equivalent
    # node — the highest-value signal per §6.2. A pure self-loop (self-attach)
    # never shows up via nx.descendants (which excludes the source node), so
    # it's folded in explicitly via ``self_node in admin_nodes``.
    escalation_graph = nx.DiGraph(
        (u, v)
        for u, v, d in g.edges(data=True)
        if d.get("relation") in ("CAN_ASSUME", "CAN_ESCALATE")
    )
    reachable_for_escalation = (
        nx.descendants(escalation_graph, self_node) if self_node in escalation_graph else set()
    )
    self_as_target = {self_node} if self_node in admin_nodes else set()
    admin_targets = (reachable_for_escalation | self_as_target) & admin_nodes
    can_reach_admin = bool(admin_targets)

    if can_reach_admin and self_node not in direct_admin_nodes:
        # Not worth recording a path if the principal is already flat-out
        # admin today — that's the plain iam.principal.admin_access finding's
        # job. Prefer a path to a genuinely *other* admin principal when one
        # exists (a richer, more concrete story than "I could self-grant");
        # fall back to the self-attach primitive only when that's all there is.
        other_targets = sorted(admin_targets - {self_node})
        hop_nodes = _shortest_of(escalation_graph, self_node, other_targets)
        if hop_nodes:
            target = hop_nodes[-1]
            via_labels = [
                (g.get_edge_data(u, v) or {}).get("via")
                or (g.get_edge_data(u, v) or {}).get("relation", "")
                for u, v in zip(hop_nodes, hop_nodes[1:], strict=False)
            ]
            escalations.setdefault(p.principal_uid, []).append(
                EscalationPath(
                    principal_uid=p.principal_uid,
                    hops=[n.split(":", 1)[1] for n in hop_nodes],
                    via=",".join(via_labels) or "direct",
                    target_uid=target.split(":", 1)[1],
                )
            )
        elif self_node in self_escalating:
            escalations.setdefault(p.principal_uid, []).append(
                EscalationPath(
                    principal_uid=p.principal_uid,
                    hops=[p.principal_uid],
                    via=self_escalating[self_node],
                    target_uid=p.principal_uid,
                )
            )

    # Step 4: the blast-radius formula, verbatim from §6.2.
    def norm(x: int, cap: int) -> float:
        return min(x, cap) / cap

    blast = 100 * (
        _W_SENSITIVE * norm(reachable_sensitive, _SENSITIVE_CAP)
        + _W_ACTIONS * norm(reachable_actions, _ACTIONS_CAP)
        + _W_ADMIN * (1 if can_reach_admin else 0)
        + _W_ROLES * norm(len(assumable_role_uids), _ROLES_CAP)
    )

    p.blast_radius_score = int(round(min(100, max(0, blast))))
    p.reachable_actions = reachable_actions
    p.reachable_sensitive = reachable_sensitive
