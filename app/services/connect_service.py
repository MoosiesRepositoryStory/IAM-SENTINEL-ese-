"""Connect-account orchestration for the web wizard (§5.3).

Wraps ``create_account`` + ``run_scan`` behind one call with the same
per-method validation a real cloud-onboarding form would do, so the wizard's
"Assume Role (simulated)" path can genuinely reject a malformed ARN before
ever touching the (mocked) scan — a deliberate showpiece of onboarding UX,
per the spec, even though it transparently maps to the same moto org as the
one-click demo path.
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy.orm import Session

from app.domain.records import Thresholds
from app.models import Run
from app.services.account_service import create_account
from app.services.scan_service import ScanError, run_scan

CONNECTION_METHODS = ("demo", "assume_role", "upload")

_ROLE_ARN_RE = re.compile(r"^arn:aws:iam::\d{12}:role/[\w+=,.@-]+$")


class ConnectError(RuntimeError):
    """Bad wizard input or a failed scan; the caller re-renders the wizard with
    this message rather than a raw 500."""


def connect_account(
    session: Session,
    *,
    name: str,
    method: str,
    thresholds: Thresholds,
    role_arn: str | None = None,
    external_id: str | None = None,
    inventory_text: str | None = None,
    policies_json: str | None = None,
    logs_text: str | None = None,
    actor_id: int | None = None,
) -> Run:
    name = (name or "").strip()
    if not name:
        raise ConnectError("Account name is required.")
    if method not in CONNECTION_METHODS:
        raise ConnectError(f"Unknown connection method: {method!r}")

    source_config: dict[str, Any] = {**thresholds.to_dict()}
    account_external_id: str | None = None

    if method in ("demo", "assume_role"):
        source_type = "moto_aws"
        if method == "assume_role":
            role_arn = (role_arn or "").strip()
            if not _ROLE_ARN_RE.match(role_arn):
                raise ConnectError(
                    "Role ARN must look like arn:aws:iam::<12-digit-account-id>:role/<name>."
                )
            account_external_id = (external_id or "").strip() or None
            source_config["role_arn"] = role_arn
            source_config["simulated"] = True
    else:
        source_type = "file"
        inventory_text = (inventory_text or "").strip() or None
        policies_json = (policies_json or "").strip() or None
        logs_text = (logs_text or "").strip() or None
        if not any([inventory_text, policies_json, logs_text]):
            raise ConnectError(
                "Upload at least one file: user inventory, policies, or an auth log."
            )
        source_config["inventory_text"] = inventory_text
        source_config["policies_json"] = policies_json
        source_config["logs_text"] = logs_text

    account = create_account(
        session,
        name=name,
        source_type=source_type,
        external_id=account_external_id,
        source_config=source_config,
        created_by=actor_id,
    )
    try:
        return run_scan(session, account.id, thresholds=thresholds, triggered_by=actor_id)
    except ScanError as exc:
        raise ConnectError(f"Scan failed: {exc}") from exc
