# IAM Sentinel

> Open-source cloud IAM posture and entitlement analysis — it maps who can do
> what, scores the blast radius, checks it against CIS/SOC2/NIST, and drives
> remediation through a real findings workflow. It runs entirely against a
> simulated AWS environment so you can try the whole thing in one command.

![CI](https://img.shields.io/badge/CI-pending-lightgrey)
![coverage](https://img.shields.io/badge/coverage-92%25-brightgreen)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

> **Build status:** Phase 0 (foundation & backend spine) complete. The findings
> workflow UI, simulated-cloud ingestion, blast-radius graph, API/RBAC, and
> one-command Docker demo land in Phases 1–5. See [the roadmap](#roadmap).

---

## What it demonstrates

IAM Sentinel is a portfolio piece that shows depth across security domain
knowledge (least-privilege, privilege-escalation paths, blast radius, compliance
frameworks) and engineering (clean service architecture, a real data model,
tested core logic, migrations, CI).

## Phase 0 — what works today

A pluggable analysis engine with **20 compliance-mapped checks**, wired end to
end from file ingestion to a persisted, scored, cross-run-correlated set of
findings — all behind a green quality gate.

```
# 1. Set up
python -m venv .venv && . .venv/Scripts/activate   # (bash: source .venv/bin/activate)
pip install -e ".[dev]"

# 2. Initialise the database
iam-sentinel init-db

# 3. Scan the bundled sample org
iam-sentinel scan --name "Acme Corp" \
    --inventory samples/users.csv \
    --policies samples/policies.json \
    --logs samples/auth.log \
    -o report.json

# 4. Browse the registered checks
iam-sentinel checks

# 5. (optional) run the minimal web app
flask --app app.web:create_app run
```

A scan prints an account posture score/grade and a severity breakdown, and
writes a full JSON report. The seeded "intern" surfaces as a **CRITICAL
privilege-escalation** finding (`iam:PassRole` + `iam:CreateAccessKey`).

## Architecture (Phase 0)

```
CLI / Flask
    │
    ▼
ScanService ──▶ IngestionAdapter (file) ──▶ normalize ──▶ NormalizedDataset
    │                                                            │
    │                                                            ▼
    │                                              Rule Registry (20 checks)
    │                                              + risk scoring + compliance
    ▼                                                            │
SQLAlchemy models (SQLite/WAL, Postgres-ready) ◀── persist ──────┘
    ▲
Alembic migrations
```

- `app/domain` — pure, dependency-light core (records, enums, parser,
  fingerprint, policy reader). Heavily unit- and property-tested.
- `app/analysis` — the rule registry, engine, and risk scorer.
- `app/ingestion` — source adapters + normalization.
- `app/models` + `app/db` — SQLAlchemy 2.0 schema + engine.
- `app/services` — orchestration (ScanService, export).

## Simulated cloud (design note)

Rather than a real, paid AWS account, IAM Sentinel targets a **simulated
environment** (file ingestion today; a `moto`-mocked AWS org in Phase 2). This
keeps the ingestion code path genuine while requiring no credentials, no bill,
and no flaky network — a deliberate design choice, not a limitation.

## Tech stack

Python 3.11+ · Flask · SQLAlchemy 2 + Alembic · Click · pytest + Hypothesis ·
ruff · mypy. Later phases add htmx/Alpine, RQ+Redis, boto3/moto, and networkx.

## Testing & CI

```
ruff check . && ruff format --check .
mypy app/
pytest -q --cov=app --cov-fail-under=80
```

GitHub Actions runs lint + format + type + tests + a migration smoke check on
every push. Core-logic coverage is ~92%.

## Roadmap

| Phase | Focus |
|---|---|
| **0 ✅** | Foundation & backend spine (this release) |
| 1 | Findings workflow + core UX shell |
| 2 | Simulated cloud ingestion + scheduling + diff |
| 3 | Blast-radius graph + least-privilege + compliance dashboard |
| 4 | JSON API, auth/RBAC, ticket integrations |
| 5 | Docker one-command demo, CI badges, docs, deploy |

## License

MIT — see [LICENSE](LICENSE).
