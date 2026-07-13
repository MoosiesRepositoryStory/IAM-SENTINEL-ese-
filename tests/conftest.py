"""Shared fixtures and dataset builders."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

import pytest
from app import db as db_module
from app.domain.records import (
    LogEventRecord,
    NormalizedDataset,
    PolicyRecord,
    PrincipalRecord,
)
from app.domain.timeutil import utcnow
from sqlalchemy.orm import Session


@pytest.fixture
def db_session(tmp_path, monkeypatch) -> Iterator[Session]:
    """A fresh file-backed SQLite database + session per test."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    db_module.reset_engine()
    db_module.create_all()
    session = db_module.get_sessionmaker()()
    try:
        yield session
        session.commit()
    finally:
        session.close()
        db_module.reset_engine()


def principal(uid: str, **kwargs) -> PrincipalRecord:
    return PrincipalRecord(principal_uid=uid, **kwargs)


def policy(uid: str, document: dict, **kwargs) -> PolicyRecord:
    return PolicyRecord(policy_uid=uid, name=kwargs.pop("name", uid), document=document, **kwargs)


def admin_doc() -> dict:
    return {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


@pytest.fixture
def dataset() -> NormalizedDataset:
    """A small dataset exercising a spread of checks."""
    now = utcnow()
    return NormalizedDataset(
        principals=[
            principal(
                "user/intern",
                username="intern",
                kind="user",
                console_access=True,
                mfa_enabled=False,
                active=True,
                last_login=now - timedelta(days=5),
                access_key_age_days=410,
                attached_policy_uids=["InternEscalation"],
            ),
            principal(
                "user/alice",
                username="alice",
                kind="user",
                console_access=True,
                mfa_enabled=True,
                active=True,
                last_login=now - timedelta(days=2),
                access_key_age_days=30,
                attached_policy_uids=["ReadOnly"],
            ),
        ],
        policies=[
            policy(
                "InternEscalation",
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["iam:PassRole", "iam:CreateAccessKey"],
                            "Resource": "*",
                        }
                    ]
                },
            ),
            policy(
                "ReadOnly",
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject"],
                            "Resource": ["arn:aws:s3:::b/*"],
                        }
                    ]
                },
            ),
        ],
        log_events=[
            LogEventRecord(
                ts=now, principal_uid="user/intern", event_name="ConsoleLogin", outcome="failure"
            )
        ],
    )
