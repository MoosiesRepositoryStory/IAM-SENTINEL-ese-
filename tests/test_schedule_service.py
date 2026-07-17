"""Schedule CRUD tests (§5.5 / §11.4)."""

from __future__ import annotations

import pytest
from app.domain.records import Thresholds
from app.models import Schedule
from app.services import create_account
from app.services.schedule_service import (
    ScheduleError,
    delete_schedule,
    get_schedule,
    upsert_schedule,
)
from sqlalchemy import select

pytestmark = pytest.mark.integration


def _account(session, name: str = "Acme"):
    return create_account(session, name=name, source_type="moto_aws", source_config={})


def test_upsert_creates_a_schedule_with_a_computed_next_run(db_session) -> None:
    account = _account(db_session)
    schedule = upsert_schedule(
        db_session, account_id=account.id, cron="0 2 * * *", thresholds=Thresholds(), actor_id=None
    )

    assert schedule.cron == "0 2 * * *"
    assert schedule.enabled is True
    assert schedule.next_run_at is not None
    assert schedule.last_run_at is None


def test_upsert_is_one_schedule_per_account_not_a_new_row_each_time(db_session) -> None:
    account = _account(db_session)
    first = upsert_schedule(
        db_session, account_id=account.id, cron="0 2 * * *", thresholds=Thresholds()
    )
    second = upsert_schedule(
        db_session, account_id=account.id, cron="0 3 * * *", thresholds=Thresholds()
    )

    assert first.id == second.id
    assert second.cron == "0 3 * * *"
    all_rows = db_session.scalars(select(Schedule).where(Schedule.account_id == account.id)).all()
    assert len(all_rows) == 1


def test_upsert_rejects_bad_cron_without_touching_any_row(db_session) -> None:
    account = _account(db_session)
    upsert_schedule(db_session, account_id=account.id, cron="0 2 * * *", thresholds=Thresholds())

    with pytest.raises(ScheduleError, match="Invalid cron"):
        upsert_schedule(db_session, account_id=account.id, cron="not a cron", thresholds=Thresholds())

    # The pre-existing schedule must survive a rejected edit untouched.
    schedule = get_schedule(db_session, account.id)
    assert schedule is not None
    assert schedule.cron == "0 2 * * *"


def test_upsert_rejects_empty_cron(db_session) -> None:
    account = _account(db_session)
    with pytest.raises(ScheduleError, match="required"):
        upsert_schedule(db_session, account_id=account.id, cron="   ", thresholds=Thresholds())


def test_disabling_a_schedule_clears_next_run_at(db_session) -> None:
    account = _account(db_session)
    upsert_schedule(db_session, account_id=account.id, cron="0 2 * * *", thresholds=Thresholds())

    disabled = upsert_schedule(
        db_session, account_id=account.id, cron="0 2 * * *", thresholds=Thresholds(), enabled=False
    )

    assert disabled.enabled is False
    assert disabled.next_run_at is None


def test_get_schedule_returns_none_when_account_has_none(db_session) -> None:
    account = _account(db_session)
    assert get_schedule(db_session, account.id) is None


def test_delete_schedule_removes_the_row_and_returns_its_id(db_session) -> None:
    account = _account(db_session)
    schedule = upsert_schedule(
        db_session, account_id=account.id, cron="0 2 * * *", thresholds=Thresholds()
    )

    deleted_id = delete_schedule(db_session, account.id)

    assert deleted_id == schedule.id
    assert get_schedule(db_session, account.id) is None


def test_delete_schedule_is_a_no_op_returning_none_when_nothing_exists(db_session) -> None:
    account = _account(db_session)
    assert delete_schedule(db_session, account.id) is None
