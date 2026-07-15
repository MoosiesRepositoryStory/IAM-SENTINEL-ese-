"""Simulated-AWS ingestion tests (§5.2, §10.1).

Runs the real ``MotoAwsIngestionAdapter`` against a moto-mocked org and asserts
the normalized dataset shape, genuine-boto3-derived attributes, cross-seed
determinism, and a full persisted scan. Skips cleanly when the optional
``cloud`` extra isn't installed.
"""

from __future__ import annotations

import pytest

pytest.importorskip("boto3")
pytest.importorskip("moto")

from app.analysis.engine import run_analysis  # noqa: E402
from app.domain.fingerprint import fingerprint  # noqa: E402
from app.domain.records import Thresholds  # noqa: E402
from app.ingestion import get_adapter, normalize  # noqa: E402
from app.ingestion.base import ProgressReporter, available_adapters  # noqa: E402
from app.models import Finding, FindingGroup  # noqa: E402
from app.services import create_account, run_scan  # noqa: E402
from sqlalchemy import select  # noqa: E402

pytestmark = pytest.mark.integration


def _fetch():
    adapter = get_adapter("moto_aws")
    return normalize(adapter.fetch({}, ProgressReporter()))


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


def test_scan_moto_account_end_to_end(db_session) -> None:
    """A moto_aws account scans, persists findings, and groups them open."""
    account = create_account(db_session, name="Acme (moto)", source_type="moto_aws")
    run = run_scan(db_session, account.id)

    assert run.status == "completed"
    assert run.composite_score is not None

    findings = db_session.scalars(select(Finding).where(Finding.run_id == run.id)).all()
    assert len(findings) > 20

    escalations = [
        f for f in findings if f.check_id == "iam.escalation.passrole_createkey"
    ]
    intern = [f for f in escalations if f.principal_uid.endswith(":user/intern")]
    assert intern and intern[0].severity == "CRITICAL"

    groups = db_session.scalars(
        select(FindingGroup).where(FindingGroup.account_id == account.id)
    ).all()
    assert groups and all(g.current_status == "open" for g in groups)


def test_rescan_moto_reuses_finding_groups(db_session) -> None:
    """A second moto scan correlates to the same groups (determinism → continuity)."""
    account = create_account(db_session, name="Acme (moto)", source_type="moto_aws")
    run1 = run_scan(db_session, account.id)
    ids_1 = {g.id for g in db_session.scalars(select(FindingGroup)).all()}

    run2 = run_scan(db_session, account.id)
    ids_2 = {g.id for g in db_session.scalars(select(FindingGroup)).all()}

    assert run2.id != run1.id
    assert ids_1 == ids_2  # no new groups: identical fingerprints carried forward
    for g in db_session.scalars(select(FindingGroup)).all():
        assert g.last_seen_run == run2.id
