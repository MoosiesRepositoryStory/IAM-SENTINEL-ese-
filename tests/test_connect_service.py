"""Connect-account wizard orchestration tests (§5.3, Phase 2 Slice 2)."""

from __future__ import annotations

from pathlib import Path

import pytest
from app.domain.records import Thresholds
from app.services.account_service import list_accounts
from app.services.connect_service import ConnectError, connect_account

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
            db_session, name="Acme", method="assume_role", thresholds=Thresholds(),
            role_arn="not-an-arn",
        )


def test_upload_requires_at_least_one_file(db_session) -> None:
    with pytest.raises(ConnectError, match="Upload at least one file"):
        connect_account(db_session, name="Acme", method="upload", thresholds=Thresholds())


@pytest.mark.integration
def test_demo_method_connects_and_scans(db_session) -> None:
    pytest.importorskip("boto3")
    pytest.importorskip("moto")
    run = connect_account(db_session, name="Acme Corp Demo", method="demo", thresholds=Thresholds())
    assert run.status == "completed"
    assert run.account.source_type == "moto_aws"
    assert run.summary is not None and run.summary.total_findings > 20


@pytest.mark.integration
def test_assume_role_method_maps_to_moto_and_records_metadata(db_session) -> None:
    pytest.importorskip("boto3")
    pytest.importorskip("moto")
    run = connect_account(
        db_session, name="Acme Prod", method="assume_role", thresholds=Thresholds(),
        role_arn="arn:aws:iam::123456789012:role/SentinelReadOnly", external_id="a1b2c3d4",
    )
    assert run.status == "completed"
    account = run.account
    assert account.source_type == "moto_aws"
    assert account.external_id == "a1b2c3d4"
    assert account.source_config["role_arn"] == "arn:aws:iam::123456789012:role/SentinelReadOnly"
    assert account.source_config["simulated"] is True


def test_upload_method_scans_sample_files(db_session) -> None:
    run = connect_account(
        db_session, name="Acme Files", method="upload", thresholds=Thresholds(),
        inventory_text=(_SAMPLES / "users.csv").read_text(encoding="utf-8"),
        policies_json=(_SAMPLES / "policies.json").read_text(encoding="utf-8"),
        logs_text=(_SAMPLES / "auth.log").read_text(encoding="utf-8"),
    )
    assert run.status == "completed"
    assert run.account.source_type == "file"
    assert run.summary is not None and run.summary.total_findings > 10


def test_list_accounts_reflects_latest_run(db_session) -> None:
    connect_account(
        db_session, name="Acme Files", method="upload", thresholds=Thresholds(),
        inventory_text=(_SAMPLES / "users.csv").read_text(encoding="utf-8"),
    )
    rows = list_accounts(db_session)
    assert len(rows) == 1
    assert rows[0].account.name == "Acme Files"
    assert rows[0].latest_run is not None
    assert rows[0].latest_run.status == "completed"
    assert rows[0].total_findings is not None
