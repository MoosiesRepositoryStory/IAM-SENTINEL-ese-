"""Simulated-AWS ingestion tests (§5.2, §10.1).

Runs the real ``MotoAwsIngestionAdapter`` against a moto-mocked org and asserts
the normalized dataset shape, genuine-boto3-derived attributes, cross-seed
determinism, and a full persisted scan. Skips cleanly when the optional
``cloud`` extra isn't installed.
"""

from __future__ import annotations

from collections import Counter

import pytest

pytest.importorskip("boto3")
pytest.importorskip("moto")

from app.analysis.engine import run_analysis  # noqa: E402
from app.domain.fingerprint import fingerprint  # noqa: E402
from app.domain.records import Thresholds  # noqa: E402
from app.ingestion import get_adapter, normalize  # noqa: E402
from app.ingestion.base import ProgressReporter, available_adapters  # noqa: E402
from app.models import Finding, FindingGroup, PermissionEdge, Principal  # noqa: E402
from app.services import create_account, run_scan  # noqa: E402
from app.services.diff_service import diff  # noqa: E402
from sqlalchemy import select  # noqa: E402

pytestmark = pytest.mark.integration


def _fetch():
    adapter = get_adapter("moto_aws")
    return normalize(adapter.fetch({}, ProgressReporter()))


def _fetch_at(drift_level: int):
    adapter = get_adapter("moto_aws")
    return normalize(adapter.fetch({"drift_level": drift_level}, ProgressReporter()))


def _fingerprints(findings) -> set[str]:
    return {fingerprint(f.check_id, f.principal_uid, f.resource, f.policy_uid) for f in findings}


def test_moto_adapter_is_registered() -> None:
    assert "moto_aws" in available_adapters()


def test_normalized_shape() -> None:
    """The adapter yields users + roles, policies, wired attachments, and parsed logs."""
    ds = _fetch()

    users = [p for p in ds.principals if p.kind == "user"]
    roles = [p for p in ds.principals if p.kind == "role"]
    assert len(users) == 10
    assert len(roles) == 6
    assert ds.policies, "expected managed + inline policies"
    assert ds.log_events, "expected CloudTrail events to be parsed"

    # Principal uids are the deterministic ARNs (fixed moto account), not moto's
    # random unique ids.
    intern = next(p for p in users if p.username == "intern")
    assert intern.principal_uid == "arn:aws:iam::123456789012:user/intern"

    # Attachments resolve: the intern's inline escalation policy is reachable.
    intern_policies = ds.policies_for(intern)
    assert any("iam:PassRole" in p.granted_actions for p in intern_policies)

    # A role trust document survived onto ``raw`` for the trust-wildcard check.
    public = next(p for p in roles if p.username == "PublicAssumable")
    assert public.raw.get("AssumeRolePolicyDocument", {}).get("Statement")


def test_temporal_and_identity_attributes_from_boto3() -> None:
    """Tag-carried temporal fields + genuinely-read console/MFA state materialize."""
    ds = _fetch()
    by_name = {p.username: p for p in ds.principals}

    intern = by_name["intern"]
    assert intern.access_key_age_days == 410  # from the key_age_days tag
    assert intern.last_login is not None  # from last_login_days_ago tag
    assert intern.console_access is True  # genuine get_login_profile
    assert intern.mfa_enabled is False  # genuine list_mfa_devices

    alice = by_name["alice"]
    assert alice.mfa_enabled is True  # MFA device enabled in the seed
    assert alice.console_access is True

    # Service account carries its account_type tag, so is_service is true.
    assert by_name["ci-deploy"].is_service is True
    # Well-behaved user without a login profile reads as no console access.
    assert by_name["svc-metrics"].console_access is False


def test_seed_is_deterministic_identical_fingerprints() -> None:
    """Two independent seeds must produce byte-identical fingerprint sets."""
    a = _fingerprints(run_analysis(_fetch(), Thresholds()).findings)
    b = _fingerprints(run_analysis(_fetch(), Thresholds()).findings)
    assert a == b
    assert len(a) > 20  # a rich org, not a trivial one


def test_baseline_finding_count_and_severity_mix() -> None:
    """Pins the documented clean-run baseline so a wildcard-matching or
    action-namespace regression in a shared helper gets caught here rather than
    only by a manual count comparison.

    **44 findings [7 crit / 17 high / 15 med / 5 low] as of Phase 3 Slice 3.**
    Down from Slice 1/2's 49 [7/17/20/5]: Slice 3 fixed a latent bug where
    ``UnusedGrantsCheck`` compared IAM-format grants ("s3:GetObject") against
    raw CloudTrail event names ("GetObject"), which never matched, so it fired
    for *every* principal with a sensitive grant regardless of real use. With
    the namespace fixed + a credential gate, the 8 unused_grants findings
    become 3 (intern confident, carol/svc-metrics insufficient) — alice/dave
    correctly drop (they use their grants) and the three credential-less roles
    drop (an activity check can't honestly assess them). Net -5 MEDIUM."""
    result = run_analysis(_fetch(), Thresholds())
    counts = Counter(f.severity.value for f in result.findings)
    assert len(result.findings) == 44
    assert dict(counts) == {"LOW": 5, "MEDIUM": 15, "HIGH": 17, "CRITICAL": 7}


def test_planted_anomalies_surface() -> None:
    """The deliberately-planted issues each produce their expected check."""
    findings = run_analysis(_fetch(), Thresholds()).findings
    check_ids = {f.check_id for f in findings}
    for expected in (
        "iam.escalation.passrole_createkey",  # intern inline PassRole+CreateAccessKey
        "iam.role.trust_wildcard_principal",  # PublicAssumable role
        "iam.principal.admin_access",  # AdminAccess holders
        "iam.user.mfa_disabled",  # console users w/o MFA
        "iam.credential.old_access_key",  # ancient keys
        "iam.user.service_console_access",  # ci-deploy console
        "log.repeated_login_failures",  # intern brute force
        "log.denied_sensitive_iam",  # denied iam:CreateUser
        "log.service_interactive_login",  # ci-deploy console login
    ):
        assert expected in check_ids, f"missing planted finding: {expected}"


def test_posture_score_is_non_degenerate_on_the_bad_demo_org() -> None:
    """Phase 3 Slice 5 retune: the deliberately-misconfigured moto org must
    read as a believable low-but-readable F, NOT the old uninformative 0.
    Pinned to a band (not an exact number) so the seed can gain/lose a finding
    without a brittle failure, while still guarding the 'not pegged at floor'
    property the retune exists to fix."""
    from app.analysis.risk import posture_grade

    result = run_analysis(_fetch(), Thresholds())
    assert 5 <= result.composite_score <= 25, result.composite_score
    assert posture_grade(result.composite_score) == "F"


def test_least_privilege_recommendations_over_real_log_data() -> None:
    """Both the confident and insufficient-data paths surface off the real
    moto CloudTrail: intern used none of its granted actions (plenty of events
    → confident, concrete suggested policy), while carol has zero observed
    activity (→ insufficient, no policy, flagged)."""
    import json

    findings = run_analysis(_fetch(), Thresholds()).findings
    lp = {
        f.principal_uid.rsplit("/", 1)[-1]: f
        for f in findings
        if f.check_id == "iam.least_privilege.unused_grants"
    }

    # Confident: intern, with an actual (empty = revoke) suggested policy doc.
    intern = lp["intern"]
    assert intern.evidence["confidence"] == "confident"
    assert intern.remediation_snippet is not None
    assert json.loads(intern.remediation_snippet)["Statement"] == []
    assert set(intern.evidence["unused_sensitive"]) == {
        "iam:PassRole",
        "iam:CreateAccessKey",
        "iam:AttachUserPolicy",
    }

    # Insufficient: carol has zero activity, so no confident policy is offered.
    carol = lp["carol"]
    assert carol.evidence["confidence"] == "insufficient_data"
    assert carol.remediation_snippet is None
    assert "insufficient" in carol.evidence["insufficient_reason"].lower()

    # Principals who actually use their grants are NOT flagged (the namespace
    # fix): alice uses s3:GetObject, dave uses s3:GetObject + sts:AssumeRole.
    assert "alice" not in lp
    assert "dave" not in lp
    # Credential-less roles aren't assessed by the activity check.
    assert "Vendor-Access" not in lp and "ReadOnly-Role" not in lp


def test_scan_moto_account_end_to_end(db_session) -> None:
    """A moto_aws account scans, persists findings, and groups them open."""
    account = create_account(db_session, name="Acme (moto)", source_type="moto_aws")
    run = run_scan(db_session, account.id)

    assert run.status == "completed"
    assert run.composite_score is not None

    findings = db_session.scalars(select(Finding).where(Finding.run_id == run.id)).all()
    assert len(findings) > 20

    escalations = [f for f in findings if f.check_id == "iam.escalation.passrole_createkey"]
    intern = [f for f in escalations if f.principal_uid.endswith(":user/intern")]
    assert intern and intern[0].severity == "CRITICAL"

    groups = db_session.scalars(
        select(FindingGroup).where(FindingGroup.account_id == account.id)
    ).all()
    assert groups and all(g.current_status == "open" for g in groups)


def test_scan_moto_account_populates_permission_graph(db_session) -> None:
    """Phase 3 Slice 1: blast radius + escalation graph flow end to end into
    the DB, not just the in-memory dataset."""
    account = create_account(db_session, name="Acme (moto)", source_type="moto_aws")
    run = run_scan(db_session, account.id)

    edges = db_session.scalars(select(PermissionEdge).where(PermissionEdge.run_id == run.id)).all()
    assert edges, "expected permission graph edges to be persisted"
    relations = {e.relation for e in edges}
    assert {"HAS_POLICY", "GRANTS_ACTION", "CAN_ASSUME", "CAN_ESCALATE"} <= relations

    principals = {
        p.username: p
        for p in db_session.scalars(select(Principal).where(Principal.run_id == run.id)).all()
    }
    intern, bob, dormant = principals["intern"], principals["bob"], principals["dormant"]
    # The planted escalation story: intern can mint bob's (admin) credentials.
    assert intern.blast_radius_score is not None and intern.blast_radius_score > 0
    assert bob.blast_radius_score is not None and bob.blast_radius_score > 0
    # A principal with no policies/activity at all stays at zero blast radius.
    assert dormant.blast_radius_score == 0

    escalation = next(
        f
        for f in db_session.scalars(select(Finding).where(Finding.run_id == run.id)).all()
        if f.check_id == "iam.escalation.passrole_createkey"
        and f.principal_uid.endswith(":user/intern")
    )
    assert escalation.evidence.get("graph_path", [""])[-1].endswith(":user/bob")
    assert escalation.evidence.get("graph_path_via") == "iam:CreateAccessKey"


def test_rescan_moto_reuses_finding_groups(db_session) -> None:
    """A second moto scan correlates to the same groups (determinism → continuity).

    Pinned to ``drift: False`` deliberately: this asserts the *correlation*
    property in isolation — identical input twice must produce zero new groups.
    Drift (on by default, Slice 4) intentionally changes the org between scans,
    which is a different property, covered by the drift tests below.
    """
    account = create_account(
        db_session, name="Acme (moto)", source_type="moto_aws", source_config={"drift": False}
    )
    run1 = run_scan(db_session, account.id)
    ids_1 = {g.id for g in db_session.scalars(select(FindingGroup)).all()}

    run2 = run_scan(db_session, account.id)
    ids_2 = {g.id for g in db_session.scalars(select(FindingGroup)).all()}

    assert run2.id != run1.id
    assert ids_1 == ids_2  # no new groups: identical fingerprints carried forward
    for g in db_session.scalars(select(FindingGroup)).all():
        assert g.last_seen_run == run2.id


# -- deterministic seed drift (§5.4, Slice 4) --------------------------------


def test_drift_stage_zero_is_the_pristine_baseline() -> None:
    """An explicit level 0 must be byte-identical to no level at all, so every
    direct/CLI caller of the adapter is untouched by the drift feature."""
    baseline = _fingerprints(run_analysis(_fetch(), Thresholds()).findings)
    explicit_zero = _fingerprints(run_analysis(_fetch_at(0), Thresholds()).findings)
    assert baseline == explicit_zero


def test_drift_is_deterministic_within_a_stage() -> None:
    """Slice 1's determinism guarantee must hold *per stage*: seeding stage 1
    twice still produces identical fingerprints."""
    a = _fingerprints(run_analysis(_fetch_at(1), Thresholds()).findings)
    b = _fingerprints(run_analysis(_fetch_at(1), Thresholds()).findings)
    assert a == b


def test_drift_stage_one_adds_a_bad_user_and_fixes_one_finding() -> None:
    ds0, ds1 = _fetch_at(0), _fetch_at(1)
    names_0 = {p.username for p in ds0.principals}
    names_1 = {p.username for p in ds1.principals}

    # The drifted-in contractor appears...
    assert "contractor-x" not in names_0
    assert "contractor-x" in names_1
    # ...and carol's MFA gets enrolled, which is what resolves a finding.
    assert next(p for p in ds0.principals if p.username == "carol").mfa_enabled is False
    assert next(p for p in ds1.principals if p.username == "carol").mfa_enabled is True
    # erin's key ages, changing evidence without changing identity.
    assert next(p for p in ds0.principals if p.username == "erin").access_key_age_days == 400
    assert next(p for p in ds1.principals if p.username == "erin").access_key_age_days == 800


def test_drift_stage_is_capped_so_a_third_scan_adds_no_new_churn() -> None:
    """Stage 2+ re-materializes stage 1, so a third scan's diff is legitimately
    empty rather than inventing drift the demo hasn't earned."""
    assert _fingerprints(run_analysis(_fetch_at(1), Thresholds()).findings) == _fingerprints(
        run_analysis(_fetch_at(2), Thresholds()).findings
    )


def test_second_scan_drifts_and_populates_all_three_diff_columns(db_session) -> None:
    """The end-to-end demo bar: connect → scan → scan again → a non-empty board.

    This is the one test that ties the drift seed, the scan pipeline, and
    DiffService together against real moto data; ``test_diff_service`` covers
    the set-math in isolation.
    """
    account = create_account(db_session, name="Acme (moto)", source_type="moto_aws")
    run1 = run_scan(db_session, account.id)
    run2 = run_scan(db_session, account.id)

    d = diff(db_session, run1.id, run2.id)

    assert d.new, "drift must introduce new findings"
    assert d.resolved, "drift must resolve at least one finding"
    assert d.changed, "drift must change at least one surviving finding"
    assert not d.is_empty

    # New findings all belong to the drifted-in contractor.
    assert all("contractor-x" in c.principal_uid for c in d.new)
    # The resolved one is carol's MFA finding, closed by her enrolling.
    assert [c.check_id for c in d.resolved] == ["iam.user.mfa_disabled"]
    assert "carol" in d.resolved[0].principal_uid
    # erin's key-age finding survives with only its evidence moved 400 -> 800.
    erin = next(c for c in d.changed if "erin" in c.principal_uid)
    assert [(e.key, e.before, e.after) for e in erin.delta.evidence_changes] == [
        ("key_age_days", 400, 800)
    ]
    # The account got riskier overall: a new admin-equivalent user outweighs one
    # resolved MFA finding.
    assert d.net_risk > 0


def test_drift_can_be_pinned_off_per_account(db_session) -> None:
    account = create_account(
        db_session, name="Acme (pinned)", source_type="moto_aws", source_config={"drift": False}
    )
    run1 = run_scan(db_session, account.id)
    run2 = run_scan(db_session, account.id)

    assert diff(db_session, run1.id, run2.id).is_empty
