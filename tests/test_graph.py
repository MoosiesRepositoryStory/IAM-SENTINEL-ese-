"""Permission graph & blast-radius tests (§6.2, Phase 3 Slice 1)."""

from __future__ import annotations

from app.analysis.graph import build
from app.domain.records import NormalizedDataset

from tests.conftest import admin_doc, policy, principal


def _trust(arns: list[str] | None = None, *, service: str | None = None, wildcard: bool = False) -> dict:
    if wildcard:
        principal_field: object = "*"
    elif service:
        principal_field = {"Service": service}
    else:
        principal_field = {"AWS": arns or []}
    return {
        "Statement": [{"Effect": "Allow", "Principal": principal_field, "Action": "sts:AssumeRole"}]
    }


def _role(uid: str, trust: dict, **kwargs) -> object:
    return principal(uid, kind="role", raw={"AssumeRolePolicyDocument": trust}, **kwargs)


# --- HAS_POLICY / GRANTS_ACTION / ON_RESOURCE -------------------------------


def test_policy_edges_wired_through_to_actions_and_resources() -> None:
    ds = NormalizedDataset(
        principals=[principal("user/alice", username="alice", attached_policy_uids=["ReadOnly"])],
        policies=[
            policy(
                "ReadOnly",
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject"],
                            "Resource": ["arn:aws:s3:::b/*"],
                        }
                    ]
                },
            )
        ],
    )
    result = build(ds)
    relations = {(e.src_uid, e.dst_uid, e.relation) for e in result.edges}
    assert ("user/alice", "ReadOnly", "HAS_POLICY") in relations
    assert ("ReadOnly", "s3:GetObject", "GRANTS_ACTION") in relations
    assert ("s3:GetObject", "arn:aws:s3:::b/*", "ON_RESOURCE") in relations


# --- CAN_ASSUME --------------------------------------------------------------


def test_can_assume_edge_from_trust_policy_naming_a_known_principal() -> None:
    ds = NormalizedDataset(
        principals=[
            principal("user/bob", username="bob"),
            _role("role/Break-Glass", _trust(["user/bob"]), username="Break-Glass"),
        ]
    )
    result = build(ds)
    assert any(
        e.relation == "CAN_ASSUME" and e.src_uid == "user/bob" and e.dst_uid == "role/Break-Glass"
        for e in result.edges
    )


def test_can_assume_ignores_wildcard_and_service_and_unmatched_principal() -> None:
    ds = NormalizedDataset(
        principals=[
            principal("user/bob", username="bob"),
            _role("role/Public", _trust(wildcard=True), username="Public"),
            _role("role/Lambda", _trust(service="lambda.amazonaws.com"), username="Lambda"),
            _role("role/Vendor", _trust(["arn:aws:iam::999999999999:root"]), username="Vendor"),
        ]
    )
    result = build(ds)
    assert not any(e.relation == "CAN_ASSUME" for e in result.edges)


# --- CAN_ESCALATE + blast radius ---------------------------------------------


def test_self_attach_makes_a_lone_principal_admin_reachable() -> None:
    """A principal that can attach any policy to itself is admin-equivalent on
    its own — no other admin principal needs to exist in the dataset."""
    ds = NormalizedDataset(
        principals=[
            principal(
                "user/intern",
                username="intern",
                attached_policy_uids=["SelfAttach"],
            )
        ],
        policies=[
            policy(
                "SelfAttach",
                {
                    "Statement": [
                        {"Effect": "Allow", "Action": ["iam:AttachUserPolicy"], "Resource": "*"}
                    ]
                },
            )
        ],
    )
    result = build(ds)
    intern = ds.principals[0]
    assert intern.blast_radius_score >= 20  # the can_reach_admin weight alone is 20
    path = result.escalations["user/intern"][0]
    assert path.hops == ["user/intern"]
    assert path.via == "iam:AttachUserPolicy"


def test_create_access_key_on_another_admin_records_the_shorter_path() -> None:
    """intern can mint bob's credentials; bob already holds admin directly.

    Also covers preferring the 2-hop path to bob over any longer chain.
    """
    ds = NormalizedDataset(
        principals=[
            principal(
                "user/intern",
                username="intern",
                attached_policy_uids=["CreateKey"],
            ),
            principal("user/bob", username="bob", attached_policy_uids=["Admin"]),
        ],
        policies=[
            policy(
                "CreateKey",
                {
                    "Statement": [
                        {"Effect": "Allow", "Action": ["iam:CreateAccessKey"], "Resource": "*"}
                    ]
                },
            ),
            policy("Admin", admin_doc()),
        ],
    )
    result = build(ds)
    intern = ds.principals[0]
    assert intern.blast_radius_score >= 20
    path = result.escalations["user/intern"][0]
    assert path.hops == ["user/intern", "user/bob"]
    assert path.via == "iam:CreateAccessKey"
    # bob is already admin — no escalation path recorded *for* bob.
    assert "user/bob" not in result.escalations


def test_no_escalation_primitives_means_no_can_reach_admin() -> None:
    ds = NormalizedDataset(
        principals=[
            principal(
                "user/alice", username="alice", attached_policy_uids=["ReadOnly"]
            )
        ],
        policies=[
            policy(
                "ReadOnly",
                {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]},
            )
        ],
    )
    result = build(ds)
    alice = ds.principals[0]
    assert alice.blast_radius_score < 20  # no admin-reach component
    assert result.escalations == {}


# --- blast radius via CAN_ASSUME chain ---------------------------------------


def test_assumable_admin_role_raises_blast_radius_and_reachable_counts() -> None:
    ds = NormalizedDataset(
        principals=[
            principal("user/bob", username="bob"),
            _role("role/Break-Glass", _trust(["user/bob"]), username="Break-Glass", attached_policy_uids=["Admin"]),
        ],
        policies=[policy("Admin", admin_doc())],
    )
    result = build(ds)
    bob = next(p for p in ds.principals if p.username == "bob")
    assert bob.reachable_actions == 1  # the "*" sentinel, deduped
    assert bob.reachable_sensitive == 1
    assert bob.blast_radius_score >= 20
    # bob holds no admin policy himself, so this is purely the CAN_ASSUME
    # chain reaching Break-Glass's admin grant — recorded so a future UI can
    # explain *how* a non-obviously-admin principal reaches admin.
    path = result.escalations["user/bob"][0]
    assert path.hops == ["user/bob", "role/Break-Glass"]
    assert path.via == "CAN_ASSUME"


# --- graceful degradation -----------------------------------------------------


def test_empty_dataset_returns_empty_result() -> None:
    result = build(NormalizedDataset())
    assert result.edges == []
    assert result.escalations == {}


def test_build_is_a_noop_without_networkx(monkeypatch) -> None:
    import app.analysis.graph as graph_module

    monkeypatch.setattr(graph_module, "_HAS_NETWORKX", False)
    ds = NormalizedDataset(principals=[principal("user/x", username="x")])
    result = build(ds)
    assert result.edges == []
    assert ds.principals[0].blast_radius_score == 0
