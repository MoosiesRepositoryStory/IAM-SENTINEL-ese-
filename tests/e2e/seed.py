"""Seed data for the Playwright E2E suite (see README.md).

Standalone script, not a pytest module — run once, before the server starts
(``server.py``), against the exact ``DATABASE_URL``/``DATA_DIR`` the server
will also use (two separate processes sharing one SQLite file in WAL mode,
same pattern ``app.db`` already documents for the web app + background jobs).

    python tests/e2e/seed.py

Seeds:

- The three demo accounts (``seed_demo_users`` — same idempotent seeding
  ``create_app()`` does on every boot) — read_only/analyst/admin logins the
  suite's ``login_as`` fixture drives through the real login form.
- One ``moto_aws`` account, scanned **twice**. The second scan advances the
  deterministic seed-drift stage (0 -> 1, ``scan_service._drift_level``) that
  Phase 2 Slice 4 built specifically to demo the run-to-run diff view with
  real, non-empty deltas (new/resolved/changed) rather than an empty diff —
  see ``app/services/diff_service.py``'s module docstring. This also gives
  the blast-radius graph real escalation-path data (Phase 3 Slice 1's
  ``intern -> bob`` finding), since both scans read the same moto org.
"""

from __future__ import annotations

from app.db import create_all, session_scope
from app.services import create_account, run_scan
from app.services.auth_service import seed_demo_users


def main() -> None:
    create_all()
    with session_scope() as session:
        seed_demo_users(session)
        account = create_account(
            session, name="Acme Corp", source_type="moto_aws", source_config={}
        )
        account_id = account.id

    with session_scope() as session:
        run_scan(session, account_id)
    with session_scope() as session:
        run_scan(session, account_id)

    print(f"E2E seed complete: account {account_id}, 2 completed moto_aws runs.")


if __name__ == "__main__":
    main()
