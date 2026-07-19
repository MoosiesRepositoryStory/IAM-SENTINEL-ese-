"""Shared fixtures and dataset builders."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

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


@pytest.fixture
def client(db_session):  # noqa: ANN001
    """A Flask test client wired to the same throwaway DB as ``db_session``
    (route handlers open their own ``session_scope()``, a separate connection
    to the same WAL-mode SQLite file — see app/db.py). ``start_background_jobs
    =False`` skips APScheduler: it's a process-wide singleton that would
    otherwise keep pointing at a prior test's already-torn-down engine across
    repeated ``create_app()`` calls (§ app/web/__init__.py). CSRF is disabled
    here for convenience — most tests don't care about it; the one test that
    does (verifying the login form's protection is real) builds its own app
    with CSRF left on rather than using this fixture."""
    from app.web import create_app

    app = create_app(start_background_jobs=False)
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    with app.test_client() as c:
        yield c


class CapturingHandler(BaseHTTPRequestHandler):
    """A real local HTTP server the ``local_http_server`` fixture below
    spins up, for tests that need to prove something (``WebhookAdapter``,
    §7.5) actually leaves the process rather than mocking the network call."""

    received: list[dict] = []
    respond_status = 200

    def do_POST(self) -> None:  # noqa: N802 — stdlib method name
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        CapturingHandler.received.append(
            {"path": self.path, "headers": dict(self.headers), "json": json.loads(body)}
        )
        self.send_response(CapturingHandler.respond_status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args: object) -> None:  # silence stdlib's stderr logging
        pass


@pytest.fixture
def local_http_server() -> Iterator[HTTPServer]:
    CapturingHandler.received = []
    CapturingHandler.respond_status = 200
    server = HTTPServer(("127.0.0.1", 0), CapturingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)


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
