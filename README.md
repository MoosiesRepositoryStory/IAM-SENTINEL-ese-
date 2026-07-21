# IAM Sentinel

> Open-source cloud IAM posture and entitlement analysis — it maps who can do
> what, scores the blast radius, checks it against CIS/SOC2/NIST, and drives
> remediation through a real findings workflow. It runs entirely against a
> simulated AWS environment so you can try the whole thing in one command.

[![CI](https://github.com/MoosiesRepositoryStory/IAM-SENTINEL-ese-/actions/workflows/ci.yml/badge.svg)](https://github.com/MoosiesRepositoryStory/IAM-SENTINEL-ese-/actions/workflows/ci.yml)
![coverage](https://img.shields.io/badge/coverage-92%25-brightgreen)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

> **▶ Live demo — [iam-sentinel.onrender.com](https://iam-sentinel.onrender.com)**
> Sign in with `admin@example.com` / `iam-sentinel-demo` (analyst and read-only
> demo accounts are listed on the login page). It runs on a free instance that
> sleeps when idle, so the first request after a while cold-starts in ~30–60s.
> The simulated "Acme Corp" AWS org is already scanned, so findings, the
> blast-radius graph, and the compliance dashboard are populated on arrival.

> **Build status:** Phases 0–4 complete — analysis engine, findings workflow,
> simulated-cloud ingestion, blast-radius graph, least-privilege engine,
> compliance dashboard, auth/RBAC, JSON API, and ticket/webhook integrations
> are all built and tested. Phase 5 — Docker one-command demo, CI polish, docs,
> and the live deploy above — is done. See [the roadmap](#roadmap).

---

## Repository layout

```
app/                        # the product — a Flask app + analysis engine
├── analysis/                 # rule engine: 20 compliance-mapped checks + scoring
│   ├── checks/                 # one module per check category (credential, identity,
│   │                           #   inventory, log, policy, privilege-escalation)
│   ├── engine.py                # runs the check registry over a NormalizedDataset
│   ├── graph.py                  # permission graph + blast-radius scoring (§6.2)
│   ├── least_privilege.py        # unused-grant / suggested-policy recommendations
│   ├── registry.py                # @register decorator + the check REGISTRY
│   └── risk.py                     # composite risk scoring + account posture
├── api/                       # /api/v1 JSON API (flask-smorest), separate JWT auth
├── compliance/                # CIS/SOC2/NIST control mappings
├── domain/                    # pure, dependency-light logic (fingerprinting, cron,
│                               #   log parsing, policy evaluation, records/enums)
├── ingestion/                  # adapters that turn a source into a RawDataset
│   └── moto/                     # simulated-AWS org: deterministic seed + boto3/moto
│                                 #   adapter (the "Connect → Demo" marquee path)
├── integrations/               # ticket/webhook notification adapters (Slack/Jira are
│                               #   simulated; only the webhook adapter makes a real,
│                               #   SSRF-guarded outbound call)
├── models/                     # SQLAlchemy table definitions
├── services/                   # application/orchestration layer — one module per
│                               #   feature area (scans, findings, accounts, RBAC,
│                               #   scheduling, diff, exceptions, dashboard, ...)
├── web/                        # the HTML app: routes, auth, templates, static assets
│   ├── static/                    # vendored htmx/Alpine/Cytoscape (no CDN), app CSS/JS
│   └── templates/                 # Jinja templates + htmx partials/
├── cli.py                      # `iam-sentinel` command (init-db, scan, checks, export)
├── config.py                    # Settings.from_env() + production fail-closed checks
├── db.py                         # engine/session factory
├── jobs.py                        # in-process ThreadingJobQueue (background scans)
└── scheduler.py                    # in-process APScheduler (recurring scans + expiry)

tests/                      # pytest suite (one file per service/module under test)
└── e2e/                       # committed Playwright suite — needs a live server/
                              #   browser, excluded from plain `pytest`; own README

migrations/                 # Alembic migrations
└── versions/                  # one file per schema revision

docs/                       # ARCHITECTURE_SPEC.md — the original design spec this
                            #   app was built against

samples/                    # example inventory/policies/log files for the file-upload
                            #   ingestion path (CLI + Connect wizard "Upload")

Dockerfile                  # multi-stage build → the image the live deploy runs
docker-compose.yml           # local "serious demo" stack (app + real Postgres)
docker-entrypoint.sh          # runs `alembic upgrade head`, then execs the CMD
pyproject.toml                # package + all dependency extras (dev/cloud/graph/
                              #   docker/e2e/jobs — see the file's own comments)
alembic.ini                    # Alembic config (URL is resolved at runtime, not here)
CONTRIBUTING.md                 # dev setup, test tiers, PR expectations
SECURITY.md                      # vulnerability reporting + documented security posture
CHANGELOG.md                      # what shipped in each phase/slice
```

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
| 5 ✅ | Docker one-command demo, CI badges, docs, live deploy |

See [CHANGELOG.md](CHANGELOG.md) for what shipped in each phase/slice.

## License

MIT — see [LICENSE](LICENSE).
