# IAM Sentinel

> Open-source cloud IAM posture and entitlement analysis — it maps who can do
> what, scores the blast radius, checks it against CIS/SOC2/NIST, and drives
> remediation through a real findings workflow. It runs entirely against a
> simulated AWS environment so you can try the whole thing in one command.

[![CI](https://github.com/MoosiesRepositoryStory/IAM-SENTINEL-ese-/actions/workflows/ci.yml/badge.svg)](https://github.com/MoosiesRepositoryStory/IAM-SENTINEL-ese-/actions/workflows/ci.yml)
![coverage](https://img.shields.io/badge/coverage-92%25-brightgreen)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

> **Build status:** Phases 0–4 complete — analysis engine, findings workflow,
> simulated-cloud ingestion, blast-radius graph, least-privilege engine,
> compliance dashboard, auth/RBAC, JSON API, and ticket/webhook integrations
> are all built and tested. Phase 5 (Docker one-command demo, CI polish, live
> deploy) is in progress. See [the roadmap](#roadmap).

---

## What it demonstrates

IAM Sentinel is a portfolio piece that shows depth across security domain
knowledge (least-privilege, privilege-escalation paths, blast radius, compliance
frameworks) and engineering (clean service architecture, a real data model,
tested core logic, migrations, RBAC, a documented API, CI).

## What works today

A pluggable analysis engine with **20 compliance-mapped checks**, wired end to
end from ingestion (a deterministic simulated-AWS org, or file upload) through
scoring, blast-radius graphing, least-privilege recommendations, a collaborative
findings workflow, and a JSON API — all behind role-based access control and a
green quality gate.

```
# 1. Set up
python -m venv .venv && . .venv/Scripts/activate   # (bash: source .venv/bin/activate)
pip install -e ".[dev]"

# 2. Initialise the database
iam-sentinel init-db

# 3. Run the app and log in with a seeded demo account (admin/analyst/read_only —
#    printed by seed_demo_users() on first boot; see app/services/auth_service.py)
flask --app app.web:create_app run

# 4. From the UI: Accounts → Connect → "Demo" — scans the built-in simulated
#    AWS org (moto-backed, no credentials or network needed) in seconds.
```

Prefer the CLI? The original file-ingestion path still works standalone, no
web app required:

```
iam-sentinel scan --name "Acme Corp" \
    --inventory samples/users.csv \
    --policies samples/policies.json \
    --logs samples/auth.log \
    -o report.json
iam-sentinel checks   # browse the registered checks
```

A scan prints an account posture score/grade and a severity breakdown, and
writes a full JSON report. The seeded "intern" surfaces as a **CRITICAL
privilege-escalation** finding (`iam:PassRole` + `iam:CreateAccessKey`), with
a concrete escalation path rendered in the blast-radius graph.

## Architecture

```
Browser / API client
    │                                                     ┌─ app/api  (JWT, /api/v1)
    ▼                                                     │
Flask (app/web, app/api) ──────────────────────────────────┘
    │
    ▼
ScanService ──▶ IngestionAdapter (file | moto_aws) ──▶ normalize ──▶ NormalizedDataset
    │                                                                      │
    │                                              ┌───────────────────────┤
    │                                              ▼                       ▼
    │                                   Rule Registry (20 checks)   Permission graph
    │                                   + risk scoring + compliance  + blast radius
    ▼                                              │                       │
SQLAlchemy models (SQLite/WAL, Postgres-ready) ◀── persist ────────────────┘
    ▲
Alembic migrations
    │
app/jobs (in-process queue) + app/scheduler (in-process APScheduler)
    — recurring scans, background execution, live progress
```

- `app/domain` — pure, dependency-light core (records, enums, parser,
  fingerprint, policy reader). Heavily unit- and property-tested.
- `app/analysis` — the rule registry, engine, risk scorer, permission graph
  (blast radius + escalation paths), and least-privilege recommendation engine.
- `app/ingestion` — source adapters (file, `moto`-simulated AWS) + normalization.
- `app/models` + `app/db` — SQLAlchemy 2.0 schema + engine.
- `app/services` — orchestration (ScanService, DiffService, workflow/exception/
  collaboration services, export).
- `app/web` — the Flask UI (htmx + Alpine, session auth, RBAC-gated).
- `app/api` — the JSON API (`/api/v1`, JWT-authed, OpenAPI docs at `/api/docs`).
- `app/integrations` — ticket/webhook adapters (real webhook POST; honest
  Jira/Slack stubs — no OAuth is wired up anywhere in this app).
- `app/jobs`, `app/scheduler` — in-process background execution and recurring
  scans (see `docs/ARCHITECTURE_SPEC.md`'s addendum — this superseded the
  doc's originally-planned RQ/Redis worker topology by design).

## Simulated cloud (design note)

Rather than a real, paid AWS account, IAM Sentinel targets a **simulated
environment**: a deterministic `moto`-mocked "Acme Corp" AWS org (10 users, 6
roles, 5 managed policies with a deliberate spread of misconfigurations and
deliberately-clean principals, ingested through genuine `boto3` IAM calls) is
the marquee demo path; file upload remains a fully-supported alternate
ingestion path. This keeps the ingestion code path genuine while requiring no
credentials, no bill, and no flaky network — a deliberate design choice, not a
limitation.

## Tech stack

Python 3.11+ · Flask + htmx/Alpine.js (no CDN — everything's vendored) ·
SQLAlchemy 2 + Alembic · Click · Flask-Login/Flask-WTF/argon2 (auth) ·
flask-smorest + marshmallow + PyJWT (`/api/v1`) · APScheduler (recurring
scans) · `boto3`/`moto` (simulated AWS, optional `cloud` extra) · `networkx`
(permission graph, optional `graph` extra) · pytest + Hypothesis · ruff · mypy.

## Testing & CI

```
ruff check . && ruff format --check .
mypy app/
pytest -q --cov=app --cov-fail-under=88
```

GitHub Actions runs lint + format + type + tests + a migration smoke check on
every push to `master` and on every pull request. Coverage is measured across
the whole `app` package, including `app/web` and `app/cli.py` (previously
excluded from the measured scope) — current coverage is ~92%.

## Roadmap

| Phase | Focus |
|---|---|
| 0 ✅ | Foundation & backend spine |
| 1 ✅ | Findings workflow + core UX shell |
| 2 ✅ | Simulated cloud ingestion + scheduling + diff |
| 3 ✅ | Blast-radius graph + least-privilege + compliance dashboard |
| 4 ✅ | JSON API, auth/RBAC, ticket integrations |
| 5 (in progress) | Docker one-command demo, CI badges, docs, deploy |

See [CHANGELOG.md](CHANGELOG.md) for what shipped in each phase/slice.

## License

MIT — see [LICENSE](LICENSE).
