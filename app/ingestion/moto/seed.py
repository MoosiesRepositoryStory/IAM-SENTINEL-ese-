"""Deterministic "Acme Corp" AWS org, stood up inside a moto mock (§5.2).

The org is declared as plain data below and materialized by :func:`seed_org`
through real ``boto3`` IAM calls. It is a superset of the file-based sample: a
spread of users, roles, and policies where *some* things are deliberately fine,
so the scan surfaces real findings rather than flagging everything.

Determinism: moto uses a fixed account id (``123456789012``), and every id we
key on downstream (principal ARNs, policy ARNs, policy names) is derived from
these static declarations — never from moto's random unique ids — so two seeds
produce byte-identical fingerprints.

Temporal fields (``key_age_days`` / ``last_login_days_ago`` / ``password_age_days``)
are **relative to now** and carried as IAM tags, because moto stamps every
resource with ``CreateDate = now`` and can't backdate. The adapter resolves them
against the scan time, so the demo keeps surfacing "410-day-old key" no matter
when it runs. Fingerprints exclude these values (§4.5), so this never disturbs
cross-run continuity.

**Drift (Phase 2 Slice 4).** ``seed_org(iam, drift_level=N)`` materializes the
org *as of* drift stage N — the org an account has drifted into after N scans.
Stage 0 is the pristine baseline above and is what every direct/CLI caller
gets; ``scan_service`` injects the account's completed-run ordinal so the
second scan of a demo account lands on stage 1 and the diff board has something
real to show. Drift is a pure function of the stage number (no randomness, no
wall-clock), so scanning at stage N twice still produces byte-identical
fingerprints — the Slice 1 determinism guarantee holds *per stage*.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Any

# --- policy documents ------------------------------------------------------

_ADMIN = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}
_READONLY_S3 = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": ["arn:aws:s3:::acme-reports", "arn:aws:s3:::acme-reports/*"],
        }
    ],
}
# Broad NotAction: allows everything except one action — a classic over-grant.
_DEPLOY_PIPELINE = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "NotAction": ["cloudtrail:StopLogging"], "Resource": "*"}],
}
_BILLING_READONLY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["aws-portal:View*", "ce:Get*"], "Resource": "*"}],
}
_LAMBDA_EXECUTE = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ],
}
# Privilege-escalation inline policy attached to the intern.
_INTERN_ESCALATION = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["iam:PassRole", "iam:CreateAccessKey", "iam:AttachUserPolicy"],
            "Resource": "*",
        }
    ],
}

# --- trust documents -------------------------------------------------------

_ACCOUNT_ID = "123456789012"


def _trust_service(service: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
        ],
    }


def _trust_principals(arns: list[str]) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": arns}, "Action": "sts:AssumeRole"}],
    }


# Principal '*': anyone (including external accounts) can assume it — CRITICAL.
_TRUST_WILDCARD = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}],
}


# --- declarative org -------------------------------------------------------


@dataclass(frozen=True)
class ManagedPolicySpec:
    name: str
    document: dict[str, Any]


@dataclass(frozen=True)
class UserSpec:
    name: str
    account_type: str = "human"  # human | service
    console: bool = False
    mfa: bool = False
    managed: tuple[str, ...] = ()  # managed policy names to attach
    inline: dict[str, dict[str, Any]] = field(default_factory=dict)  # name -> document
    key_age_days: int | None = None
    last_login_days_ago: int | None = None
    password_age_days: int | None = None


@dataclass(frozen=True)
class RoleSpec:
    name: str
    trust: dict[str, Any]
    managed: tuple[str, ...] = ()
    inline: dict[str, dict[str, Any]] = field(default_factory=dict)


MANAGED_POLICIES: tuple[ManagedPolicySpec, ...] = (
    ManagedPolicySpec("AdminAccess", _ADMIN),
    ManagedPolicySpec("ReadOnlyS3", _READONLY_S3),
    ManagedPolicySpec("DeployPipeline", _DEPLOY_PIPELINE),
    ManagedPolicySpec("BillingReadOnly", _BILLING_READONLY),
    ManagedPolicySpec("LambdaExecute", _LAMBDA_EXECUTE),
)

USERS: tuple[UserSpec, ...] = (
    # Over-privileged intern: inline privilege-escalation + no MFA + ancient key.
    UserSpec(
        "intern",
        console=True,
        mfa=False,
        inline={"InternEscalation": _INTERN_ESCALATION},
        key_age_days=410,
        last_login_days_ago=25,
        password_age_days=195,
    ),
    # Clean engineer: MFA on, tight policy, fresh key.
    UserSpec(
        "alice",
        console=True,
        mfa=True,
        managed=("ReadOnlyS3",),
        key_age_days=30,
        last_login_days_ago=3,
        password_age_days=40,
    ),
    # Admin with MFA — admin-equivalent finding, but hygiene is otherwise ok.
    UserSpec(
        "bob",
        console=True,
        mfa=True,
        managed=("AdminAccess",),
        key_age_days=45,
        last_login_days_ago=2,
        password_age_days=25,
    ),
    # Analyst: no MFA, inactive, stale password + old key.
    UserSpec(
        "carol",
        console=True,
        mfa=False,
        managed=("ReadOnlyS3",),
        key_age_days=120,
        last_login_days_ago=150,
        password_age_days=300,
    ),
    # Service account with console access (should never have it) + old key.
    UserSpec(
        "ci-deploy",
        account_type="service",
        console=True,
        mfa=False,
        managed=("DeployPipeline",),
        key_age_days=200,
    ),
    # Dormant contractor: never logged in, no credentials to speak of.
    UserSpec("dormant", console=False, mfa=False),
    # Well-behaved service account: no console, recent key, tight policy.
    UserSpec(
        "svc-metrics",
        account_type="service",
        console=False,
        mfa=False,
        managed=("ReadOnlyS3",),
        key_age_days=15,
    ),
    # Clean engineer #2.
    UserSpec(
        "dave",
        console=True,
        mfa=True,
        managed=("ReadOnlyS3", "LambdaExecute"),
        key_age_days=20,
        last_login_days_ago=5,
        password_age_days=30,
    ),
    # Finance analyst: no MFA + very old key.
    UserSpec(
        "erin",
        console=True,
        mfa=False,
        managed=("BillingReadOnly",),
        key_age_days=400,
        last_login_days_ago=10,
        password_age_days=60,
    ),
    # Second admin, MFA on.
    UserSpec(
        "frank",
        console=True,
        mfa=True,
        managed=("AdminAccess",),
        key_age_days=25,
        last_login_days_ago=1,
        password_age_days=15,
    ),
)

ROLES: tuple[RoleSpec, ...] = (
    # Assumable by too many principals (realism; no dedicated check until Phase 3).
    RoleSpec(
        "CI-Deploy",
        trust=_trust_principals(
            [
                f"arn:aws:iam::{_ACCOUNT_ID}:user/ci-deploy",
                f"arn:aws:iam::{_ACCOUNT_ID}:user/dave",
                f"arn:aws:iam::{_ACCOUNT_ID}:user/frank",
                f"arn:aws:iam::{_ACCOUNT_ID}:root",
            ]
        ),
        managed=("DeployPipeline",),
    ),
    # Cross-account vendor access.
    RoleSpec(
        "Vendor-Access",
        trust=_trust_principals(["arn:aws:iam::210987654321:root"]),
        managed=("ReadOnlyS3",),
    ),
    # Trust policy Principal '*' — CRITICAL.
    RoleSpec("PublicAssumable", trust=_TRUST_WILDCARD, managed=("ReadOnlyS3",)),
    # Break-glass admin role.
    RoleSpec(
        "Break-Glass",
        trust=_trust_principals([f"arn:aws:iam::{_ACCOUNT_ID}:user/bob"]),
        managed=("AdminAccess",),
    ),
    # Tight read-only role.
    RoleSpec(
        "ReadOnly-Role",
        trust=_trust_principals([f"arn:aws:iam::{_ACCOUNT_ID}:user/alice"]),
        managed=("ReadOnlyS3",),
    ),
    # Lambda execution role.
    RoleSpec(
        "Lambda-Exec", trust=_trust_service("lambda.amazonaws.com"), managed=("LambdaExecute",)
    ),
)

# --- drift (Slice 4) -------------------------------------------------------

# The user that "appeared" between scans: an unmanaged contractor handed
# AdminAccess with no MFA and a long-stale key. Deliberately a *new principal*
# rather than a new policy on an existing one, so it lands as a clean set of
# NEW fingerprints rather than muddying an existing finding's deltas.
_DRIFT_USER = UserSpec(
    "contractor-x",
    console=True,
    mfa=False,
    managed=("AdminAccess",),
    key_age_days=500,
    last_login_days_ago=200,
    password_age_days=240,
)


def org_at(drift_level: int) -> tuple[tuple[UserSpec, ...], tuple[RoleSpec, ...]]:
    """The org's declared state at drift stage ``drift_level``.

    Stage 0 = the pristine baseline. Stage 1 (and, for now, anything above it)
    applies one round of realistic drift chosen to exercise all three diff
    columns — see ``docs/`` §5.4 / §8.9:

    - **New**: ``contractor-x`` appears (admin-equivalent, no MFA, ancient key).
    - **Resolved**: ``carol`` finally enrols MFA, closing her mfa_disabled
      finding outright.
    - **Changed**: ``erin``'s key ages 400 -> 800 days, which moves that
      finding's evidence without touching its fingerprint (§4.5 excludes
      temporal values). Carol's *remaining* findings also shift risk score,
      because the risk model's likelihood term keys off
      console-access-without-MFA — enrolling her in MFA lowers them all. That
      second-order effect is intentional: it demonstrates that a delta can come
      from re-scoring, not only from re-detection.

    Stages are cumulative and capped at 1: a third scan re-materializes stage 1
    unchanged, so its diff against the second scan is legitimately empty rather
    than inventing churn the demo hasn't earned.
    """
    if drift_level < 1:
        return USERS, ROLES

    users = tuple(
        replace(u, mfa=True)
        if u.name == "carol"
        else replace(u, key_age_days=800)
        if u.name == "erin"
        else u
        for u in USERS
    ) + (_DRIFT_USER,)
    return users, ROLES


# A throwaway but well-formed password for login profiles (console access marker).
_LOGIN_PASSWORD = "Acme-Demo-Pw!2026"  # noqa: S105 — simulated moto org, not a real secret.


def _tags(user: UserSpec) -> list[dict[str, str]]:
    tags = [{"Key": "account_type", "Value": user.account_type}]
    if user.key_age_days is not None:
        tags.append({"Key": "key_age_days", "Value": str(user.key_age_days)})
    if user.last_login_days_ago is not None:
        tags.append({"Key": "last_login_days_ago", "Value": str(user.last_login_days_ago)})
    if user.password_age_days is not None:
        tags.append({"Key": "password_age_days", "Value": str(user.password_age_days)})
    return tags


def seed_org(iam: Any, drift_level: int = 0) -> None:
    """Create the Acme org in ``iam`` (a boto3 IAM client on a moto mock) at
    drift stage ``drift_level`` (default 0 = the pristine baseline).

    Idempotent within a mock's lifetime: if the users already exist (a persistent
    moto server), it no-ops. With the per-scan ``mock_aws()`` context the org is
    rebuilt from scratch each time, which is exactly what keeps it deterministic.
    """
    if iam.list_users(MaxItems=1).get("Users"):
        return  # already seeded (persistent-mock case)

    users, roles = org_at(drift_level)

    policy_arns: dict[str, str] = {}
    for spec in MANAGED_POLICIES:
        resp = iam.create_policy(PolicyName=spec.name, PolicyDocument=json.dumps(spec.document))
        policy_arns[spec.name] = resp["Policy"]["Arn"]

    for user in users:
        iam.create_user(UserName=user.name, Tags=_tags(user))
        for pname in user.managed:
            iam.attach_user_policy(UserName=user.name, PolicyArn=policy_arns[pname])
        for iname, doc in user.inline.items():
            iam.put_user_policy(
                UserName=user.name, PolicyName=iname, PolicyDocument=json.dumps(doc)
            )
        if user.console:
            iam.create_login_profile(UserName=user.name, Password=_LOGIN_PASSWORD)
        if user.mfa:
            serial = iam.create_virtual_mfa_device(VirtualMFADeviceName=f"{user.name}-mfa")[
                "VirtualMFADevice"
            ]["SerialNumber"]
            iam.enable_mfa_device(
                UserName=user.name,
                SerialNumber=serial,
                AuthenticationCode1="123456",
                AuthenticationCode2="234567",
            )

    for role in roles:
        iam.create_role(RoleName=role.name, AssumeRolePolicyDocument=json.dumps(role.trust))
        for pname in role.managed:
            iam.attach_role_policy(RoleName=role.name, PolicyArn=policy_arns[pname])
        for iname, doc in role.inline.items():
            iam.put_role_policy(
                RoleName=role.name, PolicyName=iname, PolicyDocument=json.dumps(doc)
            )
