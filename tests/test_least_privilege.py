"""Least-privilege recommendation engine tests (§6.3, Phase 3 Slice 3).

Pure-function tests over synthetic inputs — the engine takes plain
granted/used action sets + policy records, so exact before/after shapes are
faster and more precise to construct than driving a full scan. The moto
end-to-end behaviour (intern confident / carol insufficient) is covered in
test_moto_ingestion.
"""

from __future__ import annotations

import json

from app.analysis import least_privilege as lp
from app.analysis.engine import build_activity_index
from app.analysis.registry import ActivityIndex
from app.domain.logparse import to_iam_action
from app.domain.records import LogEventRecord, NormalizedDataset, PolicyRecord


def _policy(actions: list[str], resources: list[str] | str = "*") -> PolicyRecord:
    return PolicyRecord(
        policy_uid="P",
        name="P",
        document={"Statement": [{"Effect": "Allow", "Action": actions, "Resource": resources}]},
    )


# --- action normalization ----------------------------------------------------


def test_to_iam_action_qualifies_from_event_source() -> None:
    assert to_iam_action("s3.amazonaws.com", "GetObject") == "s3:GetObject"
    assert to_iam_action("iam.amazonaws.com", "CreateUser") == "iam:CreateUser"
    assert to_iam_action("sts.amazonaws.com", "AssumeRole") == "sts:AssumeRole"


def test_to_iam_action_none_for_signin_and_unqualifiable() -> None:
    assert to_iam_action("signin.amazonaws.com", "ConsoleLogin") is None  # sign-in service
    assert to_iam_action("s3.amazonaws.com", "ConsoleLogin") is None  # non-action event
    assert to_iam_action(None, "GetObject") is None  # can't qualify without a source
    assert to_iam_action("s3.amazonaws.com", None) is None


def test_to_iam_action_passes_through_already_qualified() -> None:
    assert to_iam_action(None, "s3:GetObject") == "s3:GetObject"


# --- confident recommendations ----------------------------------------------


def test_narrows_a_wildcard_grant_to_used_actions_keeping_resource_scope() -> None:
    rec = lp.recommend(
        principal_uid="u",
        granted_actions={"s3:*", "s3:GetObject", "s3:PutObject"},
        policies=[_policy(["s3:*"], ["arn:aws:s3:::b/*"])],
        used_actions={"s3:GetObject"},
        event_count=20,
        window_days=30,
    )
    assert rec.confident
    doc = rec.suggested_policy
    assert doc is not None
    assert doc["Statement"] == [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*"}
    ]
    # Used the wildcard (via GetObject), so s3:* is not "unused".
    assert "s3:*" not in rec.unused_sensitive


def test_used_nothing_yields_empty_revoke_policy() -> None:
    rec = lp.recommend(
        principal_uid="intern",
        granted_actions={"iam:PassRole", "iam:CreateAccessKey"},
        policies=[_policy(["iam:PassRole", "iam:CreateAccessKey"])],
        used_actions=set(),
        event_count=9,
        window_days=29,
    )
    assert rec.confident
    assert rec.suggested_policy == {"Version": "2012-10-17", "Statement": []}
    assert set(rec.unused_sensitive) == {"iam:PassRole", "iam:CreateAccessKey"}
    assert rec.exceeds_threshold
    assert "detaching all policies" in rec.summary


def test_suggested_policy_json_is_valid_json() -> None:
    rec = lp.recommend(
        principal_uid="u",
        granted_actions={"s3:GetObject", "sts:AssumeRole"},
        policies=[_policy(["s3:GetObject", "sts:AssumeRole"], ["arn:aws:s3:::b/*"])],
        used_actions={"s3:GetObject", "sts:AssumeRole"},
        event_count=10,
        window_days=30,
    )
    assert rec.suggested_policy_json is not None
    parsed = json.loads(rec.suggested_policy_json)
    assert parsed["Version"] == "2012-10-17"


# --- insufficiency gates -----------------------------------------------------


def test_short_window_is_insufficient_regardless_of_events() -> None:
    rec = lp.recommend(
        principal_uid="u",
        granted_actions={"iam:PassRole"},
        policies=[_policy(["iam:PassRole"])],
        used_actions=set(),
        event_count=100,  # plenty of events...
        window_days=5,  # ...but only 5 days of them
    )
    assert not rec.confident
    assert rec.suggested_policy is None
    assert rec.suggested_policy_json is None
    assert "5 day" in rec.insufficient_reason
    assert rec.exceeds_threshold  # still worth surfacing, just not confidently


def test_too_few_events_is_insufficient_even_in_a_long_window() -> None:
    rec = lp.recommend(
        principal_uid="carol",
        granted_actions={"s3:GetObject"},
        policies=[_policy(["s3:GetObject"])],
        used_actions=set(),
        event_count=0,
        window_days=29,
    )
    assert not rec.confident
    assert rec.suggested_policy is None
    assert "0 event" in rec.insufficient_reason


def test_boundary_values_are_sufficient() -> None:
    rec = lp.recommend(
        principal_uid="u",
        granted_actions={"iam:PassRole"},
        policies=[_policy(["iam:PassRole"])],
        used_actions=set(),
        event_count=lp.MIN_PRINCIPAL_EVENTS,
        window_days=lp.MIN_WINDOW_DAYS,
    )
    assert rec.confident


# --- ratio threshold ---------------------------------------------------------


def test_below_ratio_threshold_does_not_exceed() -> None:
    # 1 of 2 sensitive grants unused = 50% < 60%.
    rec = lp.recommend(
        principal_uid="u",
        granted_actions={"s3:GetObject", "iam:PassRole"},
        policies=[_policy(["s3:GetObject", "iam:PassRole"])],
        used_actions={"s3:GetObject"},
        event_count=10,
        window_days=30,
    )
    assert rec.unused_sensitive == ["iam:PassRole"]
    assert not rec.exceeds_threshold


def test_non_sensitive_grants_are_not_counted() -> None:
    rec = lp.recommend(
        principal_uid="u",
        granted_actions={"logs:CreateLogGroup", "cloudwatch:PutMetricData"},
        policies=[_policy(["logs:CreateLogGroup", "cloudwatch:PutMetricData"])],
        used_actions=set(),
        event_count=10,
        window_days=30,
    )
    assert rec.granted_sensitive == []
    assert not rec.exceeds_threshold


# --- ActivityIndex construction ---------------------------------------------


def test_activity_index_normalizes_actions_and_counts_all_events() -> None:
    ds = NormalizedDataset(
        log_events=[
            LogEventRecord(principal_uid="u", event_name="GetObject", event_source="s3.amazonaws.com"),
            LogEventRecord(
                principal_uid="u", event_name="ConsoleLogin", event_source="signin.amazonaws.com"
            ),
            LogEventRecord(
                principal_uid="u",
                event_name="CreateUser",
                event_source="iam.amazonaws.com",
                outcome="denied",
            ),
        ]
    )
    idx = build_activity_index(ds)
    # ConsoleLogin isn't an action; the denied CreateUser wasn't exercised.
    assert idx.used_by("u") == {"s3:GetObject"}
    # ...but all three events count toward observed activity.
    assert idx.events_for("u") == 3
    assert idx.is_active("u") is True


def test_login_only_principal_is_active_but_has_no_used_actions() -> None:
    ds = NormalizedDataset(
        log_events=[
            LogEventRecord(
                principal_uid="bob", event_name="ConsoleLogin", event_source="signin.amazonaws.com"
            )
        ]
    )
    idx = build_activity_index(ds)
    assert idx.used_by("bob") == set()  # no policy actions
    assert idx.is_active("bob") is True  # but the credential is clearly in use


def test_empty_activity_index_is_inactive() -> None:
    idx = ActivityIndex()
    assert idx.is_active("nobody") is False
    assert idx.events_for("nobody") == 0
