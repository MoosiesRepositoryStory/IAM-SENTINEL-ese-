"""``MotoAwsIngestionAdapter`` — the simulated-AWS ingestion path (§5.2).

Runs real ``boto3`` IAM calls against a moto mock, then reads the seeded
CloudTrail JSONL. Returns a :class:`RawDataset` in the exact shape the file
adapter produces, so normalization and the analysis engine are none the wiser
about where the data came from.
"""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from typing import Any

from app.domain.timeutil import to_iso, utcnow
from app.ingestion.base import ProgressReporter, RawDataset
from app.ingestion.moto.seed import seed_org

_CLOUDTRAIL_JSONL = Path(__file__).with_name("cloudtrail_events.jsonl")
_REGION = "us-east-1"


def _dummy_credentials() -> None:
    """moto needs *some* credentials on the client; set inert placeholders.

    These are never used against real AWS — the whole session is intercepted by
    the moto mock — but botocore refuses to build a client without them.
    """
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
    os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
    os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
    os.environ.setdefault("AWS_DEFAULT_REGION", _REGION)


class MotoAwsIngestionAdapter:
    source_type = "moto_aws"

    def fetch(self, source_config: dict[str, Any], progress: ProgressReporter) -> RawDataset:
        # Imported here (not at module top) so the whole ingestion package still
        # imports when the optional ``cloud`` extra isn't installed.
        import boto3
        from moto import mock_aws

        _dummy_credentials()
        with mock_aws():
            iam = boto3.client("iam", region_name=_REGION)
            progress.update(10, "Seeding simulated AWS org")
            seed_org(iam)

            progress.update(25, "Listing IAM users")
            principals, attachments, policy_docs = self._read_users(iam)

            progress.update(40, "Listing roles & policies")
            role_principals, role_attachments, role_policy_docs = self._read_roles(iam)
            principals.extend(role_principals)
            attachments.extend(role_attachments)
            policy_docs.update(role_policy_docs)

        progress.update(70, "Loading CloudTrail events")
        log_events = self._load_cloudtrail()

        progress.update(90, "Normalizing")
        return RawDataset(
            principals=principals,
            policies=list(policy_docs.values()),
            log_events=log_events,
            attachments=attachments,
        )

    # -- IAM readers (all genuine boto3 round-trips) --------------------------
    def _read_users(
        self, iam: Any
    ) -> tuple[list[dict[str, Any]], list[tuple[str, str]], dict[str, dict[str, Any]]]:
        principals: list[dict[str, Any]] = []
        attachments: list[tuple[str, str]] = []
        policy_docs: dict[str, dict[str, Any]] = {}
        now = utcnow()

        for summary in _paginate(iam, "list_users", "Users"):
            name = summary["UserName"]
            uid = summary["Arn"]
            tags = _tag_map(iam.list_user_tags(UserName=name).get("Tags", []))
            policy_uids: list[str] = []

            for attached in iam.list_attached_user_policies(UserName=name).get(
                "AttachedPolicies", []
            ):
                arn = attached["PolicyArn"]
                policy_uids.append(arn)
                attachments.append((uid, arn))
                self._collect_managed_policy(iam, arn, attached["PolicyName"], policy_docs)

            for pname in iam.list_user_policies(UserName=name).get("PolicyNames", []):
                doc = iam.get_user_policy(UserName=name, PolicyName=pname)["PolicyDocument"]
                puid = f"inline:{name}:{pname}"
                policy_uids.append(puid)
                attachments.append((uid, puid))
                policy_docs[puid] = {
                    "policy_uid": puid, "name": pname, "kind": "inline", "document": doc,
                }

            account_type = tags.get("account_type", "human")
            principals.append(
                {
                    "principal_uid": uid,
                    "kind": "user",
                    "username": name,
                    "arn": uid,
                    "account_type": account_type,
                    "active": True,
                    "console_access": _has_login_profile(iam, name),
                    "mfa_enabled": bool(iam.list_mfa_devices(UserName=name).get("MFADevices")),
                    "last_login": _days_ago_iso(tags.get("last_login_days_ago"), now),
                    "password_last_changed": _days_ago_iso(tags.get("password_age_days"), now),
                    "access_key_age_days": _int_or_none(tags.get("key_age_days")),
                    "attached_policy_uids": policy_uids,
                    "raw": {"arn": uid, "tags": tags},
                }
            )
        return principals, attachments, policy_docs

    def _read_roles(
        self, iam: Any
    ) -> tuple[list[dict[str, Any]], list[tuple[str, str]], dict[str, dict[str, Any]]]:
        principals: list[dict[str, Any]] = []
        attachments: list[tuple[str, str]] = []
        policy_docs: dict[str, dict[str, Any]] = {}

        for summary in _paginate(iam, "list_roles", "Roles"):
            name = summary["RoleName"]
            uid = summary["Arn"]
            trust = summary.get("AssumeRolePolicyDocument") or {}
            policy_uids = []

            for attached in iam.list_attached_role_policies(RoleName=name).get(
                "AttachedPolicies", []
            ):
                arn = attached["PolicyArn"]
                policy_uids.append(arn)
                attachments.append((uid, arn))
                self._collect_managed_policy(iam, arn, attached["PolicyName"], policy_docs)

            for pname in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
                doc = iam.get_role_policy(RoleName=name, PolicyName=pname)["PolicyDocument"]
                puid = f"inline:{name}:{pname}"
                policy_uids.append(puid)
                attachments.append((uid, puid))
                policy_docs[puid] = {
                    "policy_uid": puid, "name": pname, "kind": "inline", "document": doc,
                }

            principals.append(
                {
                    "principal_uid": uid,
                    "kind": "role",
                    "username": name,
                    "arn": uid,
                    "account_type": "role",
                    "active": True,
                    "attached_policy_uids": policy_uids,
                    # The trust-wildcard check reads the trust doc off ``raw``.
                    "raw": {"arn": uid, "AssumeRolePolicyDocument": trust},
                }
            )
        return principals, attachments, policy_docs

    def _collect_managed_policy(
        self, iam: Any, arn: str, name: str, policy_docs: dict[str, dict[str, Any]]
    ) -> None:
        if arn in policy_docs:
            return  # shared managed policy already fetched
        meta = iam.get_policy(PolicyArn=arn)["Policy"]
        version = iam.get_policy_version(PolicyArn=arn, VersionId=meta["DefaultVersionId"])
        policy_docs[arn] = {
            "policy_uid": arn,
            "name": name,
            "kind": "managed",
            "document": version["PolicyVersion"]["Document"],
        }

    def _load_cloudtrail(self) -> list[dict[str, Any]]:
        """Read the seeded CloudTrail stream as raw lines.

        Each line is a CloudTrail-shaped JSON object; we hand them to normalization
        as ``{"line": ...}`` so the existing, tested CloudTrail parser
        (``logparse._from_cloudtrail``) does the work — no bespoke parsing here.
        """
        if not _CLOUDTRAIL_JSONL.exists():
            return []
        events: list[dict[str, Any]] = []
        for line in _CLOUDTRAIL_JSONL.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append({"line": line})
        return events


# -- module helpers ---------------------------------------------------------


def _paginate(iam: Any, method: str, key: str) -> list[dict[str, Any]]:
    """Collect all items from a paginated IAM ``list_*`` call."""
    paginator = iam.get_paginator(method)
    items: list[dict[str, Any]] = []
    for page in paginator.paginate():
        items.extend(page.get(key, []))
    return items


def _tag_map(tags: list[dict[str, str]]) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in tags}


def _has_login_profile(iam: Any, username: str) -> bool:
    try:
        iam.get_login_profile(UserName=username)
        return True
    except iam.exceptions.NoSuchEntityException:
        return False


def _int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _days_ago_iso(value: str | None, now: Any) -> str | None:
    days = _int_or_none(value)
    if days is None:
        return None
    return to_iso(now - timedelta(days=days))
