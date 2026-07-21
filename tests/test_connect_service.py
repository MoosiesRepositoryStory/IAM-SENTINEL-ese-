"""Connect-account wizard orchestration tests (§5.3, Phase 2 Slice 2).

``connect_account`` only validates + creates the account as of Slice 3 —
scanning is a separate, caller-driven ``enqueue_scan`` call (see
test_scan_service.py for that half). These tests cover validation and that
the right account shape gets created for each connection method.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from app.domain.records import Thresholds
from app.models import Account
from app.services.account_service import list_accounts
from app.services.connect_service import ConnectError, connect_account
from app.services.rbac import PermissionDenied
from sqlalchemy import select

_SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_missing_name_rejected(db_session) -> None:
    with pytest.raises(ConnectError, match="name is required"):
        connect_account(db_session, name="  ", method="demo", thresholds=Thresholds())


def test_unknown_method_rejected(db_session) -> None:
    with pytest.raises(ConnectError, match="Unknown connection method"):
        connect_account(db_session, name="Acme", method="carrier_pigeon", thresholds=Thresholds())


def test_assume_role_requires_well_formed_arn(db_session) -> None:
    with pytest.raises(ConnectError, match="Role ARN must look like"):
        connect_account(
            db_session,
            name="Acme",
            method="assume_role",
            thresholds=Thresholds(),
            role_arn="not-an-arn",
        )


def test_upload_requires_at_least_one_file(db_session) -> None:
    with pytest.raises(ConnectError, match="Upload at least one file"):
        connect_account(db_session, name="Acme", method="upload", thresholds=Thresholds())


# ---- RBAC defense-in-depth (§10.2, Phase 4 Slice 2) ----
# The route layer (require_role(Capability.CONNECT_ACCOUNT)) is the primary
# gate; these prove the service-layer re-check independently rejects a
# forged/bypassed call to connect_account() itself.


def test_connect_rejected_for_analyst_actor_role(db_session) -> None:
    with pytest.raises(PermissionDenied):
        connect_account(
            db_session,
            name="Acme",
            method="demo",
            thresholds=Thresholds(),
            actor_role="analyst",
        )
    assert db_session.scalars(select(Account)).all() == []


def test_connect_rejected_for_read_only_actor_role(db_session) -> None:
    with pytest.raises(PermissionDenied):
        connect_account(
            db_session,
            name="Acme",
            method="demo",
            thresholds=Thresholds(),
            actor_role="read_only",
        )


def test_connect_allowed_for_admin_actor_role(db_session) -> None:
    account_id = connect_account(
        db_session,
        name="Acme",
        method="demo",
        thresholds=Thresholds(),
        actor_role="admin",
    )
    assert db_session.get(Account, account_id) is not None


def test_connect_actor_role_none_is_trusted_unchecked(db_session) -> None:
    """The default ``actor_role=None`` means "trusted internal caller, no
    check" — every pre-existing test above that omits it must keep working
    unchanged."""
    account_id = connect_account(db_session, name="Acme", method="demo", thresholds=Thresholds())
    assert db_session.get(Account, account_id) is not None


def test_demo_method_creates_a_moto_account(db_session) -> None:
    account_id = connect_account(
        db_session, name="Acme Corp Demo", method="demo", thresholds=Thresholds()
    )
    account = db_session.get(Account, account_id)
    assert account is not None
    assert account.source_type == "moto_aws"


def test_assume_role_method_maps_to_moto_and_records_metadata(db_session) -> None:
    account_id = connect_account(
        db_session,
        name="Acme Prod",
        method="assume_role",
        thresholds=Thresholds(),
        role_arn="arn:aws:iam::123456789012:role/SentinelReadOnly",
        external_id="a1b2c3d4",
    )
    account = db_session.get(Account, account_id)
    assert account is not None
    assert account.source_type == "moto_aws"
    assert account.external_id == "a1b2c3d4"
    assert account.source_config["role_arn"] == "arn:aws:iam::123456789012:role/SentinelReadOnly"
    assert account.source_config["simulated"] is True


def test_upload_method_creates_a_file_account(db_session) -> None:
    account_id = connect_account(
        db_session,
        name="Acme Files",
        method="upload",
        thresholds=Thresholds(),
        inventory_text=(_SAMPLES / "users.csv").read_text(encoding="utf-8"),
        policies_json=(_SAMPLES / "policies.json").read_text(encoding="utf-8"),
        logs_text=(_SAMPLES / "auth.log").read_text(encoding="utf-8"),
    )
    account = db_session.get(Account, account_id)
    assert account is not None
    assert account.source_type == "file"
    assert account.source_config["inventory_text"]


def test_list_accounts_reflects_no_run_before_a_scan_is_enqueued(db_session) -> None:
    connect_account(
        db_session,
        name="Acme Files",
        method="upload",
        thresholds=Thresholds(),
        inventory_text=(_SAMPLES / "users.csv").read_text(encoding="utf-8"),
    )
    rows = list_accounts(db_session)
    assert len(rows) == 1
    assert rows[0].account.name == "Acme Files"
    assert rows[0].latest_run is None
