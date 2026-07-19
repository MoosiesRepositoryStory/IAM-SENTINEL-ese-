"""Check tests: positive + negative + threshold boundaries (§12.1)."""

from __future__ import annotations

from datetime import timedelta

from app.analysis.registry import REGISTRY, ActivityIndex, CheckContext
from app.domain.records import NormalizedDataset, Thresholds
from app.domain.timeutil import utcnow

from tests.conftest import admin_doc, policy, principal


def _run_check(check_id: str, dataset: NormalizedDataset, thresholds=None, activity=None):
    ctx = CheckContext(
        dataset=dataset,
        thresholds=thresholds or Thresholds(),
        activity=activity or ActivityIndex(),
    )
    return list(REGISTRY[check_id].run(ctx))


# --- mfa_disabled ------------------------------------------------------------
def test_mfa_disabled_fires_for_console_user_without_mfa() -> None:
    ds = NormalizedDataset(
        principals=[principal("user/x", username="x", console_access=True, mfa_enabled=False)]
    )
    findings = _run_check("iam.user.mfa_disabled", ds)
    assert len(findings) == 1
    assert findings[0].principal_uid == "user/x"


def test_mfa_disabled_silent_when_mfa_enabled_or_no_console() -> None:
    ds = NormalizedDataset(
        principals=[
            principal("user/a", username="a", console_access=True, mfa_enabled=True),
            principal("user/b", username="b", console_access=False, mfa_enabled=False),
        ]
    )
    assert _run_check("iam.user.mfa_disabled", ds) == []


# --- old_access_key threshold boundary --------------------------------------
def test_old_access_key_boundary() -> None:
    ds = NormalizedDataset(
        principals=[
            principal("user/at", username="at", access_key_age_days=90),  # exactly at limit
            principal("user/under", username="under", access_key_age_days=89),
        ]
    )
    findings = _run_check("iam.credential.old_access_key", ds, Thresholds(key_age_days=90))
    uids = {f.principal_uid for f in findings}
    assert uids == {"user/at"}  # >= threshold fires; strictly-under does not


# --- inactive user -----------------------------------------------------------
def test_inactive_user_uses_threshold() -> None:
    now = utcnow()
    ds = NormalizedDataset(
        principals=[
            principal(
                "user/old", username="old", active=True, last_login=now - timedelta(days=200)
            ),
            principal("user/new", username="new", active=True, last_login=now - timedelta(days=10)),
        ]
    )
    findings = _run_check("iam.user.inactive", ds, Thresholds(inactivity_days=90))
    assert {f.principal_uid for f in findings} == {"user/old"}


# --- admin access ------------------------------------------------------------
def test_admin_access_detected() -> None:
    ds = NormalizedDataset(
        principals=[principal("user/root", username="root", attached_policy_uids=["Admin"])],
        policies=[policy("Admin", admin_doc())],
    )
    findings = _run_check("iam.principal.admin_access", ds)
    assert len(findings) == 1
    assert findings[0].severity.value == "HIGH"


# --- escalation (the golden critical) ---------------------------------------
def test_passrole_escalation_is_critical() -> None:
    doc = {
        "Statement": [
            {"Effect": "Allow", "Action": ["iam:PassRole", "iam:CreateAccessKey"], "Resource": "*"}
        ]
    }
    ds = NormalizedDataset(
        principals=[principal("user/intern", username="intern", attached_policy_uids=["Esc"])],
        policies=[policy("Esc", doc)],
    )
    findings = _run_check("iam.escalation.passrole_createkey", ds)
    assert len(findings) == 1
    assert findings[0].severity.value == "CRITICAL"
    assert "iam:PassRole" in findings[0].evidence["escalation_path"]


def test_passrole_without_partner_does_not_fire() -> None:
    doc = {"Statement": [{"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}]}
    ds = NormalizedDataset(
        principals=[principal("user/x", username="x", attached_policy_uids=["P"])],
        policies=[policy("P", doc)],
    )
    assert _run_check("iam.escalation.passrole_createkey", ds) == []


# --- policy wildcard ---------------------------------------------------------
def test_wildcard_action_check() -> None:
    ds = NormalizedDataset(policies=[policy("W", admin_doc())])
    assert len(_run_check("policy.wildcard_action", ds)) == 1


def test_tight_policy_produces_no_wildcard_finding() -> None:
    doc = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:x"]}]}
    ds = NormalizedDataset(policies=[policy("Tight", doc)])
    assert _run_check("policy.wildcard_action", ds) == []


# --- NotResource: sensitive_action_on_star / overly_broad_resource ----------
def test_sensitive_action_on_not_resource_is_treated_as_broad() -> None:
    """A sensitive action scoped by NotResource (applies to everything
    except one resource) is structurally as broad as Resource '*' — must
    still fire, not be missed because the excluded resource isn't the
    literal string '*'."""
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:PassRole"],
                "NotResource": "arn:aws:iam::123456789012:role/one-safe-role",
            }
        ]
    }
    ds = NormalizedDataset(policies=[policy("Broad", doc)])
    findings = _run_check("policy.sensitive_action_on_star", ds)
    assert len(findings) == 1


def test_non_sensitive_not_resource_grant_is_overly_broad() -> None:
    # s3:ListBucket (unlike s3:GetObject) isn't in the sensitive catalog, so
    # this exercises overly_broad_resource rather than sensitive_action_on_star.
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "NotResource": "arn:aws:s3:::one-excluded-bucket",
            }
        ]
    }
    ds = NormalizedDataset(policies=[policy("Broad2", doc)])
    findings = _run_check("policy.overly_broad_resource", ds)
    assert len(findings) == 1


# --- trust wildcard principal ------------------------------------------------
def _role_with_trust(uid: str, trust: dict):
    return principal(uid, kind="role", raw={"AssumeRolePolicyDocument": trust})


def test_trust_wildcard_principal_fires_for_scalar_star() -> None:
    trust = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}
    ds = NormalizedDataset(principals=[_role_with_trust("role/Public", trust)])
    findings = _run_check("iam.role.trust_wildcard_principal", ds)
    assert len(findings) == 1
    assert findings[0].severity.value == "CRITICAL"


def test_trust_wildcard_principal_ignores_deny_statement() -> None:
    """A Deny statement naming Principal '*' grants nothing — it must not be
    reported as an assumable-by-anyone trust (false positive)."""
    trust = {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole"}]}
    ds = NormalizedDataset(principals=[_role_with_trust("role/Locked", trust)])
    assert _run_check("iam.role.trust_wildcard_principal", ds) == []


def test_trust_wildcard_principal_ignores_unrelated_action() -> None:
    """Principal '*' on a statement that isn't an sts:AssumeRole grant isn't a
    public-assume trust at all."""
    trust = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:TagSession"}]}
    ds = NormalizedDataset(principals=[_role_with_trust("role/Unrelated", trust)])
    assert _run_check("iam.role.trust_wildcard_principal", ds) == []


def test_trust_wildcard_principal_catches_list_valued_wildcard() -> None:
    """``{"AWS": ["*", "arn:...:root"]}`` grants anyone via a list-valued
    Principal — a real AWS shape a bare scalar '*' check misses entirely
    (false negative)."""
    trust = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": ["*", "arn:aws:iam::210987654321:root"]},
                "Action": "sts:AssumeRole",
            }
        ]
    }
    ds = NormalizedDataset(principals=[_role_with_trust("role/ListWildcard", trust)])
    findings = _run_check("iam.role.trust_wildcard_principal", ds)
    assert len(findings) == 1


# --- log: repeated login failures -------------------------------------------
def test_repeated_login_failures_threshold(dataset) -> None:
    from app.domain.records import LogEventRecord

    now = utcnow()
    events = [
        LogEventRecord(
            ts=now,
            principal_uid="user/x",
            source_ip="1.2.3.4",
            event_name="ConsoleLogin",
            outcome="failure",
        )
        for _ in range(5)
    ]
    ds = NormalizedDataset(log_events=events)
    findings = _run_check("log.repeated_login_failures", ds, Thresholds(failed_logins=5))
    assert len(findings) == 1
    assert findings[0].evidence["failure_count"] == 5
