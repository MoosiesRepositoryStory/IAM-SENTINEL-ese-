"""User administration + last-active-admin lockout tests (§10.3, Phase 4
Slice 3)."""

from __future__ import annotations

import contextlib
import threading

import pytest
from app.models import AppUser, AuditEvent
from app.services.auth_service import hash_password, verify_password
from app.services.user_service import (
    LastAdminError,
    UserError,
    active_admin_count,
    create_user,
    list_users,
    set_active,
    update_role,
)
from sqlalchemy import select

pytestmark = pytest.mark.integration


def _user(session, *, email="u@x.local", role="analyst", active=True) -> AppUser:
    user = AppUser(
        email=email, display_name="U", password_hash=hash_password("whatever1"),
        role=role, is_active=active,
    )
    session.add(user)
    session.flush()
    return user


# ---- create_user ----


def test_create_user_success(db_session) -> None:
    user = create_user(
        db_session, email="New@Example.com", display_name="New Person",
        role="analyst", password="a-long-password",
    )
    assert user.email == "new@example.com"  # normalized
    assert user.is_active is True
    assert verify_password(user.password_hash, "a-long-password") is True


def test_create_user_writes_audit_event(db_session) -> None:
    user = create_user(
        db_session, email="a@x.local", display_name="A", role="admin",
        password="a-long-password", actor_id=None,
    )
    events = db_session.scalars(select(AuditEvent).where(AuditEvent.action == "user_created")).all()
    assert len(events) == 1
    assert events[0].target == f"app_user:{user.id}"
    assert events[0].event_metadata["role"] == "admin"


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"email": "  ", "display_name": "X", "role": "analyst", "password": "longenough"}, "Email is required"),
        ({"email": "x@y.z", "display_name": " ", "role": "analyst", "password": "longenough"}, "Display name is required"),
        ({"email": "x@y.z", "display_name": "X", "role": "superuser", "password": "longenough"}, "Invalid role"),
        ({"email": "x@y.z", "display_name": "X", "role": "analyst", "password": "short"}, "at least 8 characters"),
    ],
)
def test_create_user_validation(db_session, kwargs, match) -> None:
    with pytest.raises(UserError, match=match):
        create_user(db_session, **kwargs)


def test_create_user_duplicate_email_rejected(db_session) -> None:
    _user(db_session, email="dupe@x.local")
    with pytest.raises(UserError, match="already exists"):
        create_user(
            db_session, email="dupe@x.local", display_name="Other",
            role="analyst", password="a-long-password",
        )


def test_list_users_ordered_by_creation(db_session) -> None:
    a = _user(db_session, email="a@x.local")
    b = _user(db_session, email="b@x.local")
    rows = list_users(db_session)
    assert [r.id for r in rows] == [a.id, b.id]


# ---- last-active-admin lockout: deactivate path ----


def test_deactivate_non_last_admin_succeeds(db_session) -> None:
    _user(db_session, email="admin1@x.local", role="admin")
    admin2 = _user(db_session, email="admin2@x.local", role="admin")
    set_active(db_session, admin2.id, False)
    assert admin2.is_active is False


def test_deactivate_last_active_admin_blocked(db_session) -> None:
    only_admin = _user(db_session, email="admin@x.local", role="admin")
    with pytest.raises(LastAdminError, match="last active admin"):
        set_active(db_session, only_admin.id, False)
    assert only_admin.is_active is True  # unchanged


def test_deactivate_last_admin_still_blocked_with_other_inactive_admins(db_session) -> None:
    """A deactivated admin doesn't count toward the floor — only ACTIVE
    admins do."""
    active_admin = _user(db_session, email="admin1@x.local", role="admin", active=True)
    _user(db_session, email="admin2@x.local", role="admin", active=False)
    with pytest.raises(LastAdminError):
        set_active(db_session, active_admin.id, False)


def test_deactivate_non_admin_never_blocked_regardless_of_admin_count(db_session) -> None:
    only_admin = _user(db_session, email="admin@x.local", role="admin")
    analyst = _user(db_session, email="analyst@x.local", role="analyst")
    set_active(db_session, analyst.id, False)  # must not raise
    assert analyst.is_active is False
    assert only_admin.is_active is True


def test_deactivating_an_already_inactive_user_is_a_harmless_no_op(db_session) -> None:
    """Re-deactivating an already-inactive admin must not trip the lockout —
    they aren't propping up the active-admin floor in the first place."""
    _user(db_session, email="admin1@x.local", role="admin")  # the one active admin
    admin2 = _user(db_session, email="admin2@x.local", role="admin", active=False)
    set_active(db_session, admin2.id, False)  # already inactive — must not raise
    assert admin2.is_active is False


# ---- last-active-admin lockout: demote path ----


def test_demote_non_last_admin_succeeds(db_session) -> None:
    _user(db_session, email="admin1@x.local", role="admin")
    admin2 = _user(db_session, email="admin2@x.local", role="admin")
    update_role(db_session, admin2.id, "analyst")
    assert admin2.role == "analyst"


def test_demote_last_active_admin_blocked(db_session) -> None:
    only_admin = _user(db_session, email="admin@x.local", role="admin")
    with pytest.raises(LastAdminError, match="last active admin"):
        update_role(db_session, only_admin.id, "read_only")
    assert only_admin.role == "admin"  # unchanged


def test_demote_last_admin_to_admin_noop_never_blocked(db_session) -> None:
    """Setting the same role ('admin' -> 'admin') is not a demotion and must
    never trip the lockout, even for the sole admin."""
    only_admin = _user(db_session, email="admin@x.local", role="admin")
    update_role(db_session, only_admin.id, "admin")  # must not raise
    assert only_admin.role == "admin"


def test_promoting_someone_to_admin_never_blocked(db_session) -> None:
    _user(db_session, email="admin@x.local", role="admin")
    analyst = _user(db_session, email="analyst@x.local", role="analyst")
    update_role(db_session, analyst.id, "admin")  # increases admin count — never blocked
    assert analyst.role == "admin"


def test_demoting_an_inactive_admin_never_blocked(db_session) -> None:
    """An inactive admin isn't propping up the floor in the first place, so
    demoting them can't newly violate it."""
    _user(db_session, email="admin1@x.local", role="admin")  # the one active admin
    inactive_admin = _user(db_session, email="admin2@x.local", role="admin", active=False)
    update_role(db_session, inactive_admin.id, "read_only")  # must not raise
    assert inactive_admin.role == "read_only"


def test_update_role_invalid_role_rejected(db_session) -> None:
    user = _user(db_session, email="u@x.local", role="analyst")
    with pytest.raises(UserError, match="Invalid role"):
        update_role(db_session, user.id, "superuser")


def test_update_role_writes_audit_event(db_session) -> None:
    _user(db_session, email="admin1@x.local", role="admin")
    user = _user(db_session, email="u@x.local", role="analyst")
    update_role(db_session, user.id, "admin", actor_id=None)
    events = db_session.scalars(select(AuditEvent).where(AuditEvent.action == "user_role_changed")).all()
    assert len(events) == 1
    assert events[0].event_metadata == {"from": "analyst", "to": "admin"}


# ---- active_admin_count ----


def test_active_admin_count(db_session) -> None:
    a = _user(db_session, email="a@x.local", role="admin", active=True)
    _user(db_session, email="b@x.local", role="admin", active=False)
    _user(db_session, email="c@x.local", role="analyst", active=True)
    assert active_admin_count(db_session) == 1
    assert active_admin_count(db_session, excluding=a.id) == 0


# ---- last-active-admin lockout: concurrency (§10.3 hardening) --------------
#
# The tests above all share one long-lived `db_session` fixture, sequentially
# — real concurrency needs two independent sessions/connections racing
# against the same underlying (file-backed) SQLite DB, mirroring how two
# concurrent HTTP requests would each get their own fresh session from
# `session_scope()`. `db_session` itself just provides the throwaway
# DATABASE_URL/engine setup; these tests open their own sessions via
# `get_sessionmaker()` and commit the seed data before racing so both
# threads see it.


def _force_both_reads_before_either_decides(monkeypatch) -> None:
    """Without this, GIL scheduling tends to run one thread's whole
    read-decide-write-commit critical section to completion before the other
    thread gets a timeslice at all (each step here is fast, in-process, and
    doesn't block on real I/O long enough to force a switch) — so a plain
    `threading.Barrier` at the *start* of each thread doesn't reliably force
    the actual overlap the race depends on, making a test built on that alone
    a coin flip rather than a real proof either way.

    This inserts a second barrier inside `active_admin_count` itself (what
    `update_role`/`set_active` call to decide whether the action is allowed)
    so, absent the lock fix, BOTH threads are guaranteed to have completed
    their read before either proceeds — deterministically reproducing "both
    threads read the pre-race count" instead of leaving it to scheduling
    luck. With the fix in place, the *second* thread never reaches this
    point until the first has already committed (it's blocked earlier, on
    `_lock_active_admins`'s own SQLite/Postgres lock) — so the barrier times
    out waiting for a partner that isn't coming, and each side just proceeds
    with its own real read either way. Either way, the underlying
    `active_admin_count` value returned is always the genuine one; only its
    *timing* relative to the other thread is being controlled here."""
    import app.services.user_service as user_service_module

    real_active_admin_count = user_service_module.active_admin_count
    read_barrier = threading.Barrier(2)

    def synced_active_admin_count(session, *, excluding=None):  # noqa: ANN001
        result = real_active_admin_count(session, excluding=excluding)
        # A partner that never arrives (e.g. still blocked acquiring the lock
        # this test is proving works) just times out here -- proceed with our
        # own real read regardless.
        with contextlib.suppress(threading.BrokenBarrierError):
            read_barrier.wait(timeout=2)
        return result

    monkeypatch.setattr(user_service_module, "active_admin_count", synced_active_admin_count)


def test_concurrent_deactivation_of_last_two_admins_only_one_succeeds(db_session, monkeypatch) -> None:
    """Two admins, A and B. Thread 1 deactivates B; thread 2 deactivates A,
    at the same moment. Without a lock, both threads' reads land before
    either commits — both see "the other admin is still active" — and both
    would succeed, leaving zero active admins. With the lock, one thread's
    write blocks until the other commits, so it re-reads the post-commit
    count and is correctly rejected."""
    admin_a = _user(db_session, email="admin-a@x.local", role="admin")
    admin_b = _user(db_session, email="admin-b@x.local", role="admin")
    db_session.commit()  # durably visible to the two independent sessions below
    _force_both_reads_before_either_decides(monkeypatch)

    from app.db import get_sessionmaker

    session_factory = get_sessionmaker()
    start_barrier = threading.Barrier(2)
    results: dict[str, object] = {}
    lock = threading.Lock()

    def deactivate(name: str, target_id: int) -> None:
        session = session_factory()
        try:
            start_barrier.wait(timeout=5)
            try:
                set_active(session, target_id, False)
                session.commit()
                outcome: object = "succeeded"
            except LastAdminError as exc:
                session.rollback()
                outcome = ("rejected", str(exc))
        finally:
            session.close()
        with lock:
            results[name] = outcome

    t1 = threading.Thread(target=deactivate, args=("t1_deactivates_b", admin_b.id))
    t2 = threading.Thread(target=deactivate, args=("t2_deactivates_a", admin_a.id))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert not t1.is_alive() and not t2.is_alive()
    outcomes = list(results.values())
    assert outcomes.count("succeeded") == 1, results
    rejections = [o for o in outcomes if isinstance(o, tuple) and o[0] == "rejected"]
    assert len(rejections) == 1, results
    assert "last active admin" in rejections[0][1]

    # Exactly one of the two admins ended up deactivated — never both, never
    # neither — verified via a fresh session, not `db_session`'s own
    # (possibly stale pre-race) view.
    verify_session = session_factory()
    try:
        assert active_admin_count(verify_session) == 1
    finally:
        verify_session.close()


def test_concurrent_demotion_of_last_two_admins_only_one_succeeds(db_session, monkeypatch) -> None:
    """Same race as above, through update_role() (demote to analyst) instead
    of set_active() — both entry points call the same lock."""
    admin_a = _user(db_session, email="admin-a@x.local", role="admin")
    admin_b = _user(db_session, email="admin-b@x.local", role="admin")
    db_session.commit()
    _force_both_reads_before_either_decides(monkeypatch)

    from app.db import get_sessionmaker

    session_factory = get_sessionmaker()
    start_barrier = threading.Barrier(2)
    results: dict[str, object] = {}
    lock = threading.Lock()

    def demote(name: str, target_id: int) -> None:
        session = session_factory()
        try:
            start_barrier.wait(timeout=5)
            try:
                update_role(session, target_id, "analyst")
                session.commit()
                outcome: object = "succeeded"
            except LastAdminError as exc:
                session.rollback()
                outcome = ("rejected", str(exc))
        finally:
            session.close()
        with lock:
            results[name] = outcome

    t1 = threading.Thread(target=demote, args=("t1_demotes_b", admin_b.id))
    t2 = threading.Thread(target=demote, args=("t2_demotes_a", admin_a.id))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert not t1.is_alive() and not t2.is_alive()
    outcomes = list(results.values())
    assert outcomes.count("succeeded") == 1, results
    assert sum(1 for o in outcomes if isinstance(o, tuple) and o[0] == "rejected") == 1, results

    verify_session = session_factory()
    try:
        assert active_admin_count(verify_session) == 1
    finally:
        verify_session.close()


def test_admin_lock_query_compiles_to_for_update_on_postgres_but_not_sqlite() -> None:
    """Documents *why* two different mechanisms are needed per dialect
    (rather than exercising real multi-connection Postgres locking, which
    isn't available in this environment — no psycopg driver/server here):
    Postgres supports row locks, so `SELECT ... FOR UPDATE` is the natural
    per-row lock; SQLAlchemy's SQLite dialect silently drops `FOR UPDATE`
    entirely (SQLite has no row-level locking), which is exactly why the
    SQLite branch of `_lock_active_admins` uses `BEGIN IMMEDIATE` instead."""
    from app.services.user_service import _active_admin_ids_query
    from sqlalchemy.dialects import postgresql, sqlite

    query = _active_admin_ids_query().with_for_update()
    pg_sql = str(query.compile(dialect=postgresql.dialect()))
    sqlite_sql = str(query.compile(dialect=sqlite.dialect()))
    assert "FOR UPDATE" in pg_sql.upper()
    assert "FOR UPDATE" not in sqlite_sql.upper()
