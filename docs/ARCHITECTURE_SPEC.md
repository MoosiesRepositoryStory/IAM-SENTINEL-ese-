# IAM Sentinel — Architecture & Build Specification

> **Document type:** Senior-staff-level software architecture and implementation brief
> **Status:** Ready for implementation
> **Audience:** The implementing engineer or AI coding agent (assume zero prior context)
> **Deliverable framing:** A portfolio-defining Cloud IAM security posture management (CIEM/CSPM-lite) platform, evolved from an existing Python CLI + Flask tool.

---

## Table of Contents

1. [Executive Summary & Product Vision](#1-executive-summary--product-vision)
2. [Competitive Framing](#2-competitive-framing)
3. [System Architecture](#3-system-architecture)
4. [Data Model](#4-data-model)
5. [Ingestion & Simulated Cloud Integration](#5-ingestion--simulated-cloud-integration)
6. [Analysis Engine Design](#6-analysis-engine-design)
7. [Findings Workflow & Collaboration](#7-findings-workflow--collaboration)
8. [UX & Interaction Design](#8-ux--interaction-design-the-down-to-the-smallest-right-click-section)
9. [API Design](#9-api-design)
10. [Auth & Authorization](#10-auth--authorization-design)
11. [Background Jobs & Scheduling](#11-background-jobs--scheduling)
12. [Testing Strategy](#12-testing-strategy)
13. [DevEx & Repo Polish](#13-devex--repo-polish-plan)
14. [Phased Build Roadmap](#14-phased-build-roadmap)
15. [Risks & Scope Management](#15-risks--scope-management)

---

## 1. Executive Summary & Product Vision

### 1.1 What this project is

**IAM Sentinel** is a cloud identity and access security posture platform. It ingests identity, policy, and activity data from a cloud environment (real or simulated), runs a pluggable rule engine plus graph-based analysis to surface security findings, scores and prioritizes those findings, maps them to compliance frameworks, and drives them through a collaborative remediation workflow — all behind a polished, keyboard-driven web application with a documented JSON API.

It starts from an existing, genuinely functional codebase:

- A Python CLI (`iam_audit.py`) that loads IAM user inventory (CSV + optional REST merge), loads AWS-style policy JSON, parses auth logs (regex plaintext + JSON/CloudTrail lines), runs rule-based checks producing `Finding` records, persists runs to SQLite, and exports JSON/CSV.
- A Flask web app: marketing landing page, dashboard upload form with editable thresholds, results page with filterable findings table and severity chips, a run history page, and JSON/CSV download links.

The goal is not to rewrite what works — the rule engine, log parser, and SQLite persistence are keepers — but to **grow it into something that reads, at a glance, like a commercial product** in the class of Prowler, ScoutSuite, Wiz, AWS IAM Access Analyzer, and Datadog CSPM.

### 1.2 Who it's "for"

This is a **portfolio piece**. The real "customer" is a hiring manager, senior engineer, or security lead browsing a GitHub repository and a live demo. The project must demonstrate, in one artifact, competence across:

- **Security domain knowledge** — IAM least-privilege, privilege escalation paths, blast radius, credential hygiene, compliance frameworks (CIS AWS Foundations, SOC 2, NIST 800-53).
- **Backend engineering** — clean service architecture, a real data model, background jobs, an OpenAPI-documented API, authentication and RBAC.
- **Frontend / UX engineering** — a dense, professional, keyboard-navigable data application (not a Bootstrap form), with the interaction depth of a tool people use all day.
- **Engineering hygiene** — tests with coverage, CI, Docker one-command spin-up, structured logging, documentation.

The framing everywhere in copy, README, and demo should be: *"a security engineer's IAM posture tool."* It does **not** need real paying users, multi-tenancy at scale, or a real AWS bill.

### 1.3 What "done" looks like

"Done" is deliberately staged (see [Section 14](#14-phased-build-roadmap)), but the **north-star definition of done** is:

A visitor can:

1. Run `docker compose up` and reach a seeded, working app in under two minutes.
2. Log in (admin or read-only demo accounts pre-seeded).
3. Click **"Connect Account"**, pick the simulated "Acme Corp AWS" environment, and trigger a scan that runs as a background job with a live progress bar.
4. Land on a findings dashboard: composite risk score, severity/category breakdown, compliance posture, and a dense, sortable, virtualized findings table.
5. Right-click a finding and get a real context menu (view evidence, suppress with expiry, assign, create ticket, copy as Markdown/JSON, re-run check).
6. Drive a finding Open -> Investigating -> Resolved with a visible audit trail.
7. Open a **blast-radius graph** for an over-privileged principal.
8. Compare two scan runs in a **diff view** (new / resolved / unchanged findings).
9. Hit `Cmd/Ctrl+K` for a command palette and `j/k` to move through findings.
10. Read a README with screenshots, an architecture diagram, and a green CI badge.

Every one of those is specified concretely below.

### 1.4 Product naming & vocabulary (use consistently)

| Term | Meaning |
|---|---|
| **Account** | A simulated (or real) cloud account/environment being audited. |
| **Scan / Run** | One execution of ingestion + analysis against an Account at a point in time. |
| **Principal** | An identity: IAM user, role, or service account. |
| **Finding** | A single detected issue tied to a principal/policy/log, with severity, category, risk score, status. |
| **Check / Rule** | A unit of detection logic in the rule registry that emits Findings. |
| **Blast radius** | The set of resources/actions reachable from a principal via its granted permissions. |
| **Exception / Suppression** | An accepted-risk or suppressed Finding, optionally time-boxed. |

---

## 2. Competitive Framing

The point of naming commercial tools is to set the **feature bar** and to be explicit about **what we intentionally do not build**. We are emulating capabilities, not competing for market share.

| Tool | What it does | What IAM Sentinel emulates | What we intentionally scope down |
|---|---|---|---|
| **Prowler** | Open-source CLI running hundreds of AWS/Azure/GCP checks mapped to CIS/SOC2/etc., outputs JSON/HTML/CSV. | Pluggable rule registry, compliance framework mapping, multi-format export, severity model. | We ship ~20-30 well-crafted checks, not 300+; single simulated cloud, not multi-cloud. |
| **ScoutSuite** | Multi-cloud posture assessment, generates a static HTML report with per-service findings and a rule ruleset engine. | Rule ruleset concept, rich report/dashboard presentation. | No static-HTML dump; we build a live interactive app instead. |
| **Wiz** | Commercial CNAPP: agentless graph of cloud resources, attack-path/blast-radius analysis, risk prioritization. | The **security graph + blast-radius** concept and composite risk prioritization — this is our marquee "wow" feature. | Simulated data only; IAM-focused graph, not full-resource CNAPP. |
| **AWS IAM Access Analyzer** | AWS-native: finds resources shared externally, unused access, generates least-privilege policies from CloudTrail. | **Least-privilege recommendations inferred from activity logs** (used-vs-granted diff) and unused-credential detection. | We approximate from a simulated CloudTrail event stream, not real Access Analyzer APIs. |
| **Datadog CSPM** | Continuous posture monitoring, findings workflow (mute/assign), compliance dashboards, ticketing integrations. | **Findings workflow** (status, assignment, audit trail, suppression with expiry), compliance dashboard, ticket/webhook integration. | Integrations are abstracted/stubbed (generic webhook + Jira/Slack adapters), not full SaaS connectors. |

**The intentional scope-down that makes this buildable by one hobbyist:** we replace a real, paid, permissioned AWS account with a **`moto`-mocked AWS environment** seeded with a realistic org. This keeps the boto3 ingestion code path *real and demonstrable* (recruiters see genuine AWS SDK usage) while requiring no cloud account, no credentials, no bill, and no flaky network. This is the single most important architectural decision in the project and should be highlighted in the README as a deliberate design choice, not a limitation.

**Positioning one-liner for the README:** *"IAM Sentinel is an open-source cloud IAM posture and entitlement analysis platform — it maps who can do what, scores the blast radius, checks it against CIS/SOC2/NIST, and drives remediation through a real findings workflow. It runs entirely against a simulated AWS environment so you can try the whole thing in one command."*

---

## 3. System Architecture

### 3.1 Component overview (ASCII)

```
                                  ┌───────────────────────────────────────────┐
                                  │                 BROWSER                    │
                                  │   Server-rendered Jinja2 + htmx + Alpine   │
                                  │   Hyperscript for interactions             │
                                  │   Tabulator/Custom virtualized table       │
                                  │   Cytoscape.js for blast-radius graph      │
                                  └───────────────┬───────────────────────────┘
                                                  │ HTML over HTTP (htmx)
                                                  │ + JSON (/api/v1) + SSE (progress)
                                                  ▼
      ┌──────────────────────────────────────────────────────────────────────────────┐
      │                          FLASK APPLICATION (Gunicorn)                          │
      │                                                                                │
      │  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐   │
      │  │  Web (Jinja) │  │  JSON API    │  │  Auth / RBAC  │  │  SSE / progress  │   │
      │  │  blueprint   │  │  blueprint   │  │  (Flask-Login │  │  endpoint        │   │
      │  │              │  │  (/api/v1)   │  │   + roles)    │  │                  │   │
      │  └──────┬───────┘  └──────┬───────┘  └───────┬───────┘  └────────┬─────────┘   │
      │         └─────────────────┴──────────────────┴───────────────────┘             │
      │                                   │ calls                                       │
      │                                   ▼                                             │
      │  ┌───────────────────────────── SERVICE LAYER ───────────────────────────────┐ │
      │  │  ScanService · FindingService · WorkflowService · DiffService ·            │ │
      │  │  GraphService · RiskService · ComplianceService · ExportService ·          │ │
      │  │  IngestionService · AuthService · ScheduleService                          │ │
      │  └───────────────────────────────┬────────────────────────────────────────── ┘ │
      │                                   │                                             │
      │        ┌──────────────────────────┼───────────────────────────┐                │
      │        ▼                          ▼                           ▼                │
      │  ┌───────────┐          ┌──────────────────┐          ┌────────────────┐        │
      │  │ Rule      │          │  Ingestion       │          │  Repositories  │        │
      │  │ Registry  │          │  Adapters        │          │  (SQLAlchemy)  │        │
      │  │ (plugins) │          │  - moto/boto3    │          │                │        │
      │  │           │          │  - CSV/JSON file │          │                │        │
      │  │           │          │  - REST API      │          │                │        │
      │  └───────────┘          └────────┬─────────┘          └───────┬────────┘        │
      └───────────────────────────────────┼──────────────────────────┼─────────────────┘
                                          │ enqueue job              │ ORM
                                          ▼                          ▼
              ┌───────────────────────────────────┐        ┌──────────────────────────┐
              │        BACKGROUND WORKER           │        │        DATABASE          │
              │        (RQ + Redis)                │◄──────►│  SQLite (dev/demo)       │
              │  - runs scans off request thread   │  same  │  Postgres (prod option)  │
              │  - writes progress to Redis        │  DB    │  SQLAlchemy models       │
              │  - APScheduler enqueues recurring  │        └──────────────────────────┘
              └────────────────┬──────────────────┘
                               │ reads/writes
                               ▼
              ┌───────────────────────────────────┐        ┌──────────────────────────┐
              │   REDIS (job queue + progress +    │        │  OBJECT/FILE STORE       │
              │   pub/sub for SSE + light cache)   │        │  ./data/reports/*.json   │
              └───────────────────────────────────┘        │  (local FS; S3 optional) │
                                                            └──────────────────────────┘

              ┌─────────────────── MOTO MOCK AWS (in-process / sidecar) ───────────────┐
              │  Seeded IAM users/roles/policies + synthetic CloudTrail event stream    │
              │  Accessed via standard boto3 clients pointed at moto endpoint           │
              └────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Data flow: ingestion -> analysis -> storage -> presentation

1. **Trigger.** User clicks "Run Scan" (or a scheduled APScheduler job fires). The web/API layer calls `ScanService.enqueue_scan(account_id, options)`, which creates a `runs` row with `status='queued'` and enqueues an RQ job. The request returns immediately with a run ID.
2. **Ingestion (worker).** The RQ worker runs `IngestionService.ingest(account)`. Based on the account's `source_type`, it dispatches to an adapter:
   - `moto_aws` -> boto3 clients (iam, cloudtrail) pointed at the moto endpoint; lists users/roles/policies/attached policies, and pulls the synthetic event stream.
   - `file` -> existing CSV/JSON loaders.
   - `rest` -> existing generic REST merge.
   Ingestion normalizes everything into the canonical data model (principals, policies, permission edges, log events) and writes progress (`10% ingesting IAM…`, `40% ingesting CloudTrail…`).
3. **Analysis (worker).** `AnalysisService.run(run_id)` executes:
   - The **rule registry** — each registered check gets the normalized dataset + thresholds and yields `Finding` objects.
   - The **graph builder** — constructs permission edges and computes blast-radius metrics per principal.
   - The **least-privilege engine** — diffs used (from logs) vs granted (from policies).
   - The **risk scorer** — assigns a composite score to each finding.
   - The **compliance mapper** — tags each finding with framework control IDs.
   Progress updates stream throughout (`60% running checks…`, `85% scoring…`).
4. **Storage.** All findings, principals, policies, edges, log events, and a run summary are persisted via SQLAlchemy repositories keyed by `run_id`. A JSON report artifact is written to `./data/reports/`. Run status flips to `completed`.
5. **Presentation.** The UI polls `/api/v1/runs/{id}` (or subscribes to SSE) until complete, then renders the dashboard/findings table from the DB. Findings carry forward workflow state from prior runs via a stable **finding fingerprint** (see §4 and §5.4).

### 3.3 Technology choices (opinionated, with tradeoffs)

These are **decisions**, not menus.

#### 3.3.1 Web framework: **Keep Flask** (do not rewrite to FastAPI)

- **Decision:** Stay on Flask, add blueprints for `web`, `api`, `auth`. Use `flask-smorest` (Marshmallow-based) or `spectree`/`apispec` to auto-generate OpenAPI for the JSON API.
- **Why:** The existing app is Flask; the value here is depth, not a framework migration. Flask + Jinja + htmx gives a server-rendered app with SPA-like interactivity at a fraction of the complexity of a React build pipeline. FastAPI's async and native OpenAPI are nice, but the app is I/O-light per request (heavy work is in the worker), so async buys little, and a rewrite burns a phase for no portfolio gain.
- **Tradeoff accepted:** OpenAPI is bolt-on rather than native. Mitigated by `flask-smorest`, which makes it first-class.

#### 3.3.2 Frontend: **Server-rendered Jinja2 + htmx + Alpine.js** (not React)

- **Decision:** Jinja2 templates, **htmx** for partial updates / server round-trips (filter, sort, paginate, workflow actions), **Alpine.js** for local UI state (menus, modals, theme toggle), and one focused JS library for the heavy table (**Tabulator** or a small custom virtualized table) and one for the graph (**Cytoscape.js**).
- **Why:** htmx delivers the dense, interactive feel (context menus, inline status changes, live-updating tables) without a separate SPA, bundler, or API-versioning-for-your-own-frontend tax. It is *itself* a portfolio signal — "modern hypermedia architecture" reads as thoughtful. A React SPA would double the surface area and the maintenance for a solo builder.
- **Tradeoff accepted:** Extremely complex client state (e.g., the command palette, multi-select + keyboard nav) is more work in Alpine than in React. Mitigated by scoping those to a few well-contained Alpine components; the virtualized table is the only place we lean on a dedicated JS lib.
- **Escape hatch:** If the table interactions prove too heavy for Tabulator, isolate *just the findings table* as a small Preact/vanilla island mounted into the Jinja page. Do not SPA the whole app.

#### 3.3.3 Database: **SQLite for dev/demo, Postgres-ready via SQLAlchemy**

- **Decision:** Introduce **SQLAlchemy** ORM + **Alembic** migrations now. Default engine SQLite (`./data/sentinel.db`), with a `DATABASE_URL` env var that lets docker-compose point at Postgres.
- **Why:** SQLite makes the one-command demo trivial (no DB container required) and matches the existing persistence. SQLAlchemy + Alembic future-proofs to Postgres and signals real schema discipline. Writing raw SQL forever would undercut the "senior" framing.
- **Tradeoff accepted:** SQLite's weaker concurrency matters once a background worker writes while the web reads. Mitigated by WAL mode (`PRAGMA journal_mode=WAL`), short transactions, and the option to flip to Postgres in compose for the "serious" demo.

#### 3.3.4 Background jobs: **RQ + Redis** (not Celery, not bare threads)

- **Decision:** Use **RQ** (Redis Queue) for job execution and **APScheduler** for recurring scans (scheduler enqueues RQ jobs). Redis also backs progress state and SSE pub/sub.
- **Why:** RQ is dramatically simpler than Celery and perfect for "run this scan off the request thread with progress." Bare `threading` would block on process restarts, lose jobs, and can't scale or report cleanly — it would read as a shortcut. Celery is powerful but its config/broker/result-backend ceremony is overkill here. APScheduler handles cron-like recurring scans in-process.
- **Tradeoff accepted:** Adds Redis as a dependency. Mitigated because compose already benefits from Redis for SSE/cache, and a "fakeredis" fallback keeps unit tests dependency-free.
- **Escape hatch for the minimal cut:** If Redis must be avoided for a free-tier deploy, provide a `SYNC_JOBS=true` mode where `ScanService` runs inline in a thread with an in-memory progress store. Ship RQ as the default, though.

#### 3.3.5 Caching / real-time: **Redis + Server-Sent Events (SSE)**

- **Decision:** Progress updates and "scan complete" notifications go over **SSE** (`/api/v1/runs/{id}/events`), backed by Redis pub/sub. Fall back to polling if SSE unsupported.
- **Why:** SSE is one-directional server->client, which is exactly the progress-bar use case, and is far simpler than WebSockets (no upgrade handshake plumbing in Flask). WebSockets would be over-engineering for a progress bar.

#### 3.3.6 Object storage: **local filesystem, S3-compatible optional**

- **Decision:** JSON/CSV report artifacts write to `./data/reports/{run_id}/`. Abstract behind a tiny `ArtifactStore` interface with `LocalArtifactStore` default and an optional `S3ArtifactStore` (boto3 -> moto or MinIO) to show the seam.
- **Why:** Keeps demo zero-config; the interface demonstrates you thought about durability without forcing infra.

#### 3.3.7 Language/runtime and libraries (summary)

| Concern | Choice |
|---|---|
| Language | Python 3.11+ |
| Web | Flask 3, Jinja2, `flask-smorest` (OpenAPI), Flask-Login |
| ORM / migrations | SQLAlchemy 2.x, Alembic |
| Jobs / schedule | RQ, Redis, APScheduler |
| Cloud SDK / mock | boto3, moto |
| Graph | `networkx` (backend algorithms), Cytoscape.js (render) |
| Validation / serialization | Marshmallow (via flask-smorest) or Pydantic v2 |
| Frontend | htmx, Alpine.js, Tabulator, Cytoscape.js, minimal custom CSS (design tokens) |
| Testing | pytest, pytest-cov, Hypothesis (property-based), factory_boy, responses/moto |
| Lint/format/type | ruff (lint+format), mypy, pre-commit |
| Packaging | Docker, docker-compose, Gunicorn |
| CI | GitHub Actions |

---

## 4. Data Model

The schema is expressed as SQLAlchemy models with Alembic migrations. Below are DDL-style definitions (SQLite dialect, Postgres-compatible). Timestamps are UTC ISO-8601. All `id` columns are integer primary keys unless noted; `*_uid` columns are stable string identifiers used for cross-run correlation.

### 4.1 Entity-relationship overview

```
app_user ──< audit_event
app_user ──< finding (assignee)
account ──< run ──< finding
account ──< run ──< principal
account ──< run ──< policy
account ──< run ──< permission_edge
account ──< run ──< log_event
run ──< run_summary (1:1)
principal ──< permission_edge >── policy
finding ──< finding_comment
finding ──< finding_status_history
finding ──< finding_exception (suppression)
finding_group (fingerprint) ──< finding (across runs)
saved_view (per app_user or shared)
schedule ──< run
```

### 4.2 Core tables

#### `account` — a simulated (or real) cloud environment

```sql
CREATE TABLE account (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,               -- "Acme Corp Production"
    provider      TEXT NOT NULL DEFAULT 'aws', -- aws | azure | gcp (aws only for now)
    external_id   TEXT,                        -- simulated 12-digit AWS account id
    source_type   TEXT NOT NULL,               -- moto_aws | file | rest
    source_config JSON,                        -- adapter-specific config (endpoints, paths)
    created_at    TEXT NOT NULL,
    created_by    INTEGER REFERENCES app_user(id)
);
```

#### `run` — one scan execution

```sql
CREATE TABLE run (
    id             INTEGER PRIMARY KEY,
    account_id     INTEGER NOT NULL REFERENCES account(id),
    status         TEXT NOT NULL DEFAULT 'queued',  -- queued|ingesting|analyzing|completed|failed|canceled
    trigger        TEXT NOT NULL,                   -- manual | scheduled | api
    triggered_by   INTEGER REFERENCES app_user(id),
    schedule_id    INTEGER REFERENCES schedule(id),
    thresholds     JSON NOT NULL,                   -- inactivity_days, password_age, key_age, failed_logins
    started_at     TEXT,
    finished_at    TEXT,
    duration_ms    INTEGER,
    error_message  TEXT,
    progress_pct   INTEGER NOT NULL DEFAULT 0,
    progress_stage TEXT,                            -- human-readable current stage
    composite_score INTEGER,                        -- 0-100 account posture score for this run
    report_path    TEXT,                            -- artifact location
    created_at     TEXT NOT NULL
);
CREATE INDEX ix_run_account ON run(account_id, created_at DESC);
```

#### `run_summary` — precomputed aggregates (1:1 with run)

```sql
CREATE TABLE run_summary (
    run_id            INTEGER PRIMARY KEY REFERENCES run(id) ON DELETE CASCADE,
    total_findings    INTEGER NOT NULL,
    count_low         INTEGER NOT NULL,
    count_medium      INTEGER NOT NULL,
    count_high        INTEGER NOT NULL,
    count_critical    INTEGER NOT NULL,
    counts_by_category JSON NOT NULL,     -- {"identity": 4, "privilege": 7, ...}
    counts_by_status   JSON NOT NULL,     -- {"open": 12, "resolved": 3, ...}
    compliance_summary JSON NOT NULL,     -- {"CIS_AWS_1.4": {"pass": 18, "fail": 6}, ...}
    new_count          INTEGER,           -- vs previous run
    resolved_count     INTEGER,           -- vs previous run
    principals_total   INTEGER,
    principals_at_risk INTEGER
);
```

#### `principal` — identity snapshot per run

```sql
CREATE TABLE principal (
    id                  INTEGER PRIMARY KEY,
    run_id              INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    principal_uid       TEXT NOT NULL,      -- stable: arn or username, correlates across runs
    kind                TEXT NOT NULL,      -- user | role | service_account
    username            TEXT,
    email               TEXT,
    arn                 TEXT,
    role                TEXT,               -- business role label from CSV
    account_type        TEXT,               -- human | service | machine
    active              BOOLEAN,
    console_access      BOOLEAN,
    mfa_enabled         BOOLEAN,
    last_login          TEXT,
    password_last_changed TEXT,
    access_key_age_days INTEGER,
    attached_policy_ids JSON,               -- list of policy.id in this run
    blast_radius_score  INTEGER,            -- computed 0-100
    reachable_actions   INTEGER,            -- count of distinct actions reachable
    reachable_sensitive INTEGER,            -- count of sensitive actions reachable
    raw                 JSON                -- original row/AWS payload for evidence
);
CREATE INDEX ix_principal_run ON principal(run_id);
CREATE INDEX ix_principal_uid ON principal(principal_uid);
```

#### `policy` — policy document snapshot per run

```sql
CREATE TABLE policy (
    id            INTEGER PRIMARY KEY,
    run_id        INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    policy_uid    TEXT NOT NULL,            -- arn or name
    name          TEXT NOT NULL,
    kind          TEXT,                     -- managed | inline | aws_managed
    document      JSON NOT NULL,            -- full statement block
    statement_count INTEGER,
    has_wildcard_action  BOOLEAN,
    has_wildcard_resource BOOLEAN,
    uses_not_action BOOLEAN
);
CREATE INDEX ix_policy_run ON policy(run_id);
```

#### `permission_edge` — graph edges for blast-radius

```sql
CREATE TABLE permission_edge (
    id            INTEGER PRIMARY KEY,
    run_id        INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    src_type      TEXT NOT NULL,      -- principal | policy | action | resource
    src_uid       TEXT NOT NULL,
    dst_type      TEXT NOT NULL,
    dst_uid       TEXT NOT NULL,
    relation      TEXT NOT NULL,      -- HAS_POLICY | GRANTS_ACTION | ON_RESOURCE | CAN_ASSUME | CAN_ESCALATE
    effect        TEXT,               -- Allow | Deny
    is_sensitive  BOOLEAN DEFAULT 0,
    metadata      JSON
);
CREATE INDEX ix_edge_run_src ON permission_edge(run_id, src_uid);
```

#### `log_event` — parsed auth/CloudTrail events per run

```sql
CREATE TABLE log_event (
    id            INTEGER PRIMARY KEY,
    run_id        INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    ts            TEXT,
    principal_uid TEXT,
    source_ip     TEXT,
    event_name    TEXT,               -- ConsoleLogin | AssumeRole | iam:CreateUser ...
    event_source  TEXT,               -- signin | iam.amazonaws.com ...
    outcome       TEXT,               -- success | failure | denied
    is_privileged BOOLEAN,
    is_sensitive_iam BOOLEAN,
    raw           JSON
);
CREATE INDEX ix_log_run_principal ON log_event(run_id, principal_uid);
```

### 4.3 Findings & workflow tables

#### `finding_group` — cross-run identity of a finding

The **fingerprint** is a deterministic hash so the same underlying issue keeps its workflow state across scans.

```sql
CREATE TABLE finding_group (
    id            INTEGER PRIMARY KEY,
    account_id    INTEGER NOT NULL REFERENCES account(id),
    fingerprint   TEXT NOT NULL,      -- sha256(check_id + principal_uid + resource + policy_uid)
    check_id      TEXT NOT NULL,
    principal_uid TEXT,
    first_seen_run INTEGER REFERENCES run(id),
    last_seen_run  INTEGER REFERENCES run(id),
    current_status TEXT NOT NULL DEFAULT 'open',
    assignee_id    INTEGER REFERENCES app_user(id),
    UNIQUE(account_id, fingerprint)
);
CREATE INDEX ix_group_fingerprint ON finding_group(fingerprint);
```

#### `finding` — a finding instance within a run

```sql
CREATE TABLE finding (
    id            INTEGER PRIMARY KEY,
    run_id        INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    group_id      INTEGER NOT NULL REFERENCES finding_group(id),
    check_id      TEXT NOT NULL,         -- e.g. "iam.user.mfa_disabled"
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,         -- LOW | MEDIUM | HIGH | CRITICAL
    category      TEXT NOT NULL,         -- identity|privilege|credential|hygiene|policy|log|inventory
    principal_uid TEXT,
    resource      TEXT,
    policy_uid    TEXT,
    risk_score    INTEGER NOT NULL,      -- 0-100 composite (see §6.4)
    likelihood    INTEGER,               -- 1-5 sub-score
    impact        INTEGER,               -- 1-5 sub-score
    evidence      JSON NOT NULL,         -- structured proof (matched log lines, statement, etc.)
    recommendation TEXT NOT NULL,
    remediation_snippet TEXT,            -- copy-paste CLI/policy fix
    compliance_tags JSON,                -- ["CIS_AWS_1.4:1.14", "SOC2:CC6.1", "NIST:AC-2"]
    status        TEXT NOT NULL DEFAULT 'open',  -- denormalized from group for fast query
    created_at    TEXT NOT NULL
);
CREATE INDEX ix_finding_run ON finding(run_id, severity);
CREATE INDEX ix_finding_group ON finding(group_id);
```

> **Design note:** `finding_group` holds durable workflow state (status, assignee); `finding` is the per-run snapshot. On each scan, findings are matched to groups by fingerprint: existing groups keep their status; groups not re-emitted are considered **resolved-by-scan** (surfaced in the diff). This is exactly how commercial tools avoid "losing" your triage work between scans.

#### `finding_status_history` — the audit trail

```sql
CREATE TABLE finding_status_history (
    id            INTEGER PRIMARY KEY,
    group_id      INTEGER NOT NULL REFERENCES finding_group(id) ON DELETE CASCADE,
    from_status   TEXT,
    to_status     TEXT NOT NULL,
    actor_id      INTEGER REFERENCES app_user(id),
    note          TEXT,
    created_at    TEXT NOT NULL
);
```

#### `finding_comment`

```sql
CREATE TABLE finding_comment (
    id         INTEGER PRIMARY KEY,
    group_id   INTEGER NOT NULL REFERENCES finding_group(id) ON DELETE CASCADE,
    author_id  INTEGER NOT NULL REFERENCES app_user(id),
    body       TEXT NOT NULL,       -- markdown
    created_at TEXT NOT NULL,
    edited_at  TEXT
);
```

#### `finding_exception` — suppression / accepted-risk

```sql
CREATE TABLE finding_exception (
    id           INTEGER PRIMARY KEY,
    group_id     INTEGER NOT NULL REFERENCES finding_group(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,      -- suppressed | accepted_risk
    reason       TEXT NOT NULL,
    created_by   INTEGER NOT NULL REFERENCES app_user(id),
    created_at   TEXT NOT NULL,
    expires_at   TEXT,               -- NULL = permanent; else re-surfaces after expiry
    revoked_at   TEXT
);
```

### 4.4 App / auth / collaboration tables

#### `app_user`

```sql
CREATE TABLE app_user (
    id            INTEGER PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL,
    password_hash TEXT NOT NULL,      -- argon2 or bcrypt
    role          TEXT NOT NULL DEFAULT 'read_only',  -- admin | analyst | read_only
    is_active     BOOLEAN NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    last_login_at TEXT
);
```

#### `saved_view` — persisted filter/sort/column configs

```sql
CREATE TABLE saved_view (
    id          INTEGER PRIMARY KEY,
    owner_id    INTEGER REFERENCES app_user(id),
    name        TEXT NOT NULL,       -- "My Critical Open", "CIS Failures"
    scope       TEXT NOT NULL,       -- private | shared
    config      JSON NOT NULL,       -- {filters, sort, visible_columns, column_widths, column_order}
    is_default  BOOLEAN DEFAULT 0,
    created_at  TEXT NOT NULL
);
```

#### `schedule` — recurring scans

```sql
CREATE TABLE schedule (
    id          INTEGER PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    cron        TEXT NOT NULL,       -- APScheduler cron expression
    thresholds  JSON NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT 1,
    created_by  INTEGER REFERENCES app_user(id),
    last_run_at TEXT,
    next_run_at TEXT,
    created_at  TEXT NOT NULL
);
```

#### `audit_event` — app-level audit (logins, exports, config changes)

```sql
CREATE TABLE audit_event (
    id         INTEGER PRIMARY KEY,
    actor_id   INTEGER REFERENCES app_user(id),
    action     TEXT NOT NULL,        -- login | export_csv | create_account | run_scan | ...
    target     TEXT,
    metadata   JSON,
    ip         TEXT,
    created_at TEXT NOT NULL
);
```

### 4.5 Fingerprint algorithm (critical for cross-run continuity)

```python
def fingerprint(check_id: str, principal_uid: str | None,
                resource: str | None, policy_uid: str | None) -> str:
    parts = [check_id, principal_uid or "", resource or "", policy_uid or ""]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()
```

Rules: fingerprint must be **stable across runs** for the same logical issue and **must not** include volatile data (timestamps, run ids, counts). Evidence and risk score may change run to run; the fingerprint may not.

---

## 5. Ingestion & Simulated Cloud Integration

### 5.1 The `IngestionAdapter` interface

All sources implement one interface so the analysis engine never knows where data came from:

```python
class IngestionAdapter(Protocol):
    source_type: str
    def fetch(self, account: Account, progress: ProgressReporter) -> RawDataset: ...

@dataclass
class RawDataset:
    principals: list[dict]     # normalized principal payloads
    policies:   list[dict]     # normalized policy payloads
    log_events: list[dict]     # normalized log/CloudTrail events
    attachments: list[tuple]   # (principal_uid, policy_uid) links
```

Three concrete adapters:

1. **`FileIngestionAdapter`** — wraps the existing CSV/JSON loaders. Keep the current column contract (`username,email,role,mfa_enabled,last_login,password_last_changed,access_key_age_days,account_type,active,console_access,policies`) and the existing policy JSON loader.
2. **`RestIngestionAdapter`** — wraps the existing generic REST merge endpoint.
3. **`MotoAwsIngestionAdapter`** — the marquee new path (below).

### 5.2 The moto-mocked AWS environment

**Goal:** exercise *real* boto3 code against a *fake* AWS so the ingestion path is genuine but requires no cloud account.

**Seeding.** A `seed/seed_moto.py` module, run at container start (or lazily on first scan), stands up a realistic org inside a moto mock:

- **8-15 IAM users** with a spread of issues: some with no MFA, some with 400-day-old access keys, an inactive user who never logged out, an over-privileged "intern" with `AdministratorAccess`, a service account with console access.
- **5-8 IAM roles** including a `CI-Deploy` role assumable by too many principals, a cross-account `Vendor-Access` role, and a role whose trust policy is `Principal: *`.
- **Managed + inline policies**: at least one with `Action: "*"` on `Resource: "*"`, one with `iam:PassRole` + `iam:CreateAccessKey` (privilege escalation), one using `NotAction` broadly, and several tight, well-scoped policies (so not everything is a finding).
- **Synthetic CloudTrail stream** (`seed/cloudtrail_events.jsonl`): thousands of events over ~30 simulated days — normal `AssumeRole`/`GetObject` traffic plus planted anomalies: brute-force `ConsoleLogin` failures from one IP, a service account doing interactive `ConsoleLogin`, denied `iam:CreateUser` attempts, and a privileged user logging in from a new geography. This same stream powers the least-privilege engine (used-vs-granted).

Because moto's CloudTrail support is limited, treat CloudTrail as a **seeded JSONL event store** that the adapter reads directly, while IAM users/roles/policies are read through genuine `boto3.client("iam")` calls against moto. Document this split honestly in code comments and README.

```python
class MotoAwsIngestionAdapter:
    source_type = "moto_aws"
    def fetch(self, account, progress):
        with mock_aws():
            seed_if_empty(account)                      # idempotent
            iam = boto3.client("iam", endpoint_url=...)
            progress.update(10, "Listing IAM users")
            users = paginate(iam.list_users)
            progress.update(25, "Listing roles & policies")
            roles = paginate(iam.list_roles)
            policies = collect_attached_and_inline(iam, users, roles)
            progress.update(40, "Loading CloudTrail events")
            events = load_cloudtrail_jsonl(account)
            return normalize(users, roles, policies, events)
```

### 5.3 The "Connect Account" flow (UX for a simulated integration)

Even though it is simulated, it must *feel* like connecting a real account, because that realism is the portfolio point.

1. **Accounts page** -> **"+ Connect Account"** button opens a modal wizard.
2. **Step 1 — Provider.** Cards for AWS (enabled), Azure/GCP (greyed "coming soon"). Reinforces multi-cloud framing.
3. **Step 2 — Connection method.** Three options styled like real onboarding:
   - **"Demo environment (recommended)"** — pre-built "Acme Corp" moto org. One click.
   - **"Assume Role (simulated)"** — a form asking for Role ARN + External ID that *looks* exactly like AWS cross-account onboarding. On submit it validates format and transparently maps to the moto demo (with a small "simulated" badge). This is a deliberate showpiece of understanding real onboarding UX.
   - **"Upload files"** — CSV/JSON/logs (the existing path).
4. **Step 3 — Confirm & name.** Name the account, choose default thresholds, optionally set a scan schedule.
5. On save -> account row created -> optional immediate scan enqueued -> redirect to the account's runs page with a live progress bar.

### 5.4 Run-to-run diffing (computation & display)

**Computation** (`DiffService.diff(run_a, run_b)`), always oldest->newest:

1. Build fingerprint sets `FA`, `FB` for the two runs.
2. **New** = `FB - FA`; **Resolved** = `FA - FB`; **Unchanged** = `FA ∩ FB`.
3. For unchanged, compute **deltas**: severity change, risk-score change, status change, evidence change (e.g., failed-login count went 12 -> 40).
4. Return a `RunDiff` with counts + categorized lists + per-finding deltas.

**Display** — a dedicated **Diff view** (see §8.9): three columns (New / Unchanged-changed / Resolved), a headline banner ("+5 new, -3 resolved, net risk +18"), and colored diff badges. Also surfaced inline on the dashboard as a "Since last scan" strip. This is directly analogous to how Prowler/Wiz show drift over time and is a strong demo moment.

### 5.5 Scheduled / recurring scans

- A `schedule` row (cron expression) is created via the Connect wizard or the account settings page.
- **APScheduler** (a `BackgroundScheduler` started in the worker process, not the web process, to avoid duplicate firing under Gunicorn workers) reads enabled schedules and, at each fire time, calls `ScanService.enqueue_scan(...)` with `trigger='scheduled'`.
- Guard against multi-process double-fire with a Redis lock (`SETNX schedule:{id}:{fire_ts}`).
- After each fire, update `last_run_at`/`next_run_at`. Schedules are visible and editable in the UI with a "Run now" override.

---

## 6. Analysis Engine Design

### 6.1 Pluggable rule registry

Refactor the existing inline checks into a registry of self-describing checks. This is the single most important backend refactor for the "senior" impression.

```python
@dataclass
class CheckContext:
    dataset: NormalizedDataset       # principals, policies, edges, log_events
    thresholds: Thresholds
    graph: PermissionGraph           # prebuilt (see §6.2)
    activity: ActivityIndex          # used-actions per principal from logs

@dataclass
class CheckMeta:
    id: str                          # "iam.user.mfa_disabled"
    title: str
    category: str                    # identity|privilege|credential|hygiene|policy|log|inventory
    default_severity: str
    compliance: list[str]            # ["CIS_AWS_1.4:1.14", "SOC2:CC6.1"]
    description: str
    remediation: str

class Check(Protocol):
    meta: CheckMeta
    def run(self, ctx: CheckContext) -> Iterable[Finding]: ...

# Registration
REGISTRY: dict[str, Check] = {}
def register(check_cls):
    REGISTRY[check_cls.meta.id] = check_cls()
    return check_cls
```

Each existing rule becomes a class in `checks/` decorated with `@register`. The engine iterates the registry, passing a shared `CheckContext`; findings are collected, scored, compliance-tagged, and persisted. Benefits: each check is independently unit-testable, self-documents its compliance mapping, and new checks are one file. A `/checks` UI page can render the registry as a catalog (like Prowler's check list).

**Checks to ship (keep existing + add):**

| check_id | Category | Severity | Source |
|---|---|---|---|
| `iam.user.mfa_disabled` | identity | HIGH | existing |
| `iam.user.inactive` | hygiene | MEDIUM | existing (threshold) |
| `iam.credential.stale_password` | credential | MEDIUM | existing (threshold) |
| `iam.credential.old_access_key` | credential | HIGH | existing (threshold) |
| `iam.user.service_console_access` | identity | MEDIUM | existing |
| `policy.wildcard_action` | policy | HIGH | existing |
| `policy.sensitive_action_on_star` | privilege | HIGH | existing |
| `policy.risky_not_action` | policy | MEDIUM | existing |
| `log.repeated_login_failures` | log | MEDIUM | existing (threshold) |
| `log.privileged_login` | log | LOW | existing |
| `log.service_interactive_login` | log | HIGH | existing |
| `log.denied_sensitive_iam` | log | MEDIUM | existing |
| `iam.role.trust_wildcard_principal` | privilege | CRITICAL | new (graph) |
| `iam.escalation.passrole_createkey` | privilege | CRITICAL | new (graph) |
| `iam.principal.admin_access` | privilege | HIGH | new |
| `iam.least_privilege.unused_grants` | privilege | MEDIUM | new (activity diff) |
| `iam.credential.unused_active` | credential | MEDIUM | new (activity diff) |
| `iam.user.no_recent_login` | hygiene | LOW | new |
| `policy.overly_broad_resource` | policy | MEDIUM | new |
| `inventory.orphaned_principal` | inventory | LOW | new |

### 6.2 Permission graph & blast-radius model

**Graph construction** (`GraphService.build(dataset) -> networkx.DiGraph`):

- **Nodes:** principals, policies, actions (namespaced e.g. `s3:GetObject`), resources, and role nodes.
- **Edges** (materialized into `permission_edge` too):
  - `principal --HAS_POLICY--> policy`
  - `policy --GRANTS_ACTION--> action` (per Allow statement; Deny tracked separately)
  - `action --ON_RESOURCE--> resource`
  - `principal --CAN_ASSUME--> role` (from role trust policies / AssumeRole grants)
  - `principal --CAN_ESCALATE--> principal/role` (derived: e.g. has `iam:PassRole` + compute-launch, or `iam:CreateAccessKey` on another user, or `iam:AttachUserPolicy` on self)

**Blast-radius computation per principal:**

1. Compute the **transitive closure** of `CAN_ASSUME` edges (a principal can act as any role it can chain-assume) using `networkx.descendants`.
2. Union the granted actions across the principal and all assumable roles, subtract explicit Denies.
3. `reachable_actions` = size of that action set; `reachable_sensitive` = subset intersecting the **sensitive action catalog** (a curated list: `iam:*`, `sts:AssumeRole`, `kms:Decrypt`, `s3:*` on sensitive buckets, `ec2:RunInstances`, etc.).
4. **Blast-radius score (0-100):**

```
blast = 100 * (
    0.45 * norm(reachable_sensitive, cap=25) +
    0.25 * norm(reachable_actions, cap=300) +
    0.20 * (1 if can_reach_admin else 0) +
    0.10 * norm(assumable_roles, cap=10)
)
# norm(x, cap) = min(x, cap) / cap
```

Escalation paths (`CAN_ESCALATE` chains that reach an admin-equivalent node) are the highest-value output — each becomes a `iam.escalation.*` finding with the **path itself** rendered in the graph view and included as evidence ("intern -> PassRole -> CI-Deploy role -> AdministratorAccess").

**Rendering:** Cytoscape.js graph on the principal detail page and a dedicated Blast Radius page. Nodes colored by type, sized by blast score; sensitive edges highlighted red; the escalation path animated/emphasized. This is the "Wiz-like" wow feature.

### 6.3 Least-privilege recommendation engine

Emulates IAM Access Analyzer's "policy generation from CloudTrail."

1. Build an **ActivityIndex**: from `log_event`, map each `principal_uid -> set(actions actually used)` over the log window.
2. For each principal, compute **granted actions** (from the graph) minus **used actions** = **unused grants**.
3. Emit `iam.least_privilege.unused_grants` when unused grants include sensitive actions or exceed a ratio threshold (e.g., >60% of granted sensitive actions unused).
4. Produce a **suggested least-privilege policy**: a JSON policy document containing only the used actions on the observed resources, attached to the finding as `remediation_snippet` and copyable from the UI.
5. `iam.credential.unused_active` fires when an access key or console login has zero activity in the window but the credential is active.

Caveat to document: recommendations are only as good as the log window; surface the window length in the UI ("based on 30 days of activity").

### 6.4 Composite risk scoring

Every finding gets a **0-100 risk score** combining likelihood and impact, then adjusted by blast radius and exposure. This drives sort order and the account posture score.

**Per-finding formula:**

```
base_severity_weight = {LOW:20, MEDIUM:45, HIGH:70, CRITICAL:90}[severity]

likelihood (1-5): from evidence — e.g. active credential + external exposure + recent
                  failed logins raises it; dormant/internal lowers it.
impact (1-5):     from blast_radius_score of the affected principal and sensitivity
                  of the action/resource.

risk_score = clamp(
    0.55 * base_severity_weight +
    0.25 * (impact / 5 * 100) +
    0.20 * (likelihood / 5 * 100)
  , 0, 100)

# Modifiers (applied after):
if principal.blast_radius_score >= 75: risk_score = min(100, risk_score + 8)
if finding is on an admin/privileged principal: risk_score = min(100, risk_score + 5)
if finding.exception is active (suppressed/accepted): risk_score contribution to
    account score = 0 (but finding still stored)
```

**Account posture / composite score (0-100, higher = better):**

```
raw_risk = sum(risk_score for open, non-excepted findings)
account_score = round(100 * exp(-raw_risk / K))   # K tuned so a clean account ≈ 95-100,
                                                   # a badly misconfigured one ≈ 20-40
```

Display the account score as a large gauge with a letter grade (A-F) on the dashboard. Store per-run in `run.composite_score` so the trend is charted across runs.

### 6.5 Compliance framework mapping

Each `CheckMeta.compliance` lists control IDs. A `ComplianceService` inverts this into per-framework pass/fail summaries per run.

**Example mapping table (real CIS AWS Foundations v1.4 / SOC 2 / NIST 800-53 controls):**

| check_id | CIS AWS Foundations v1.4 | SOC 2 | NIST 800-53 |
|---|---|---|---|
| `iam.user.mfa_disabled` | 1.10 (MFA for console users) | CC6.1 | IA-2(1) |
| `iam.credential.old_access_key` | 1.14 (rotate keys ≤90d) | CC6.1 | IA-5(1) |
| `iam.credential.stale_password` | 1.9 (password policy/age) | CC6.1 | IA-5(1) |
| `iam.user.inactive` | 1.12 (disable unused creds) | CC6.2 | AC-2(3) |
| `policy.wildcard_action` | 1.16 (no full "*" policies) | CC6.3 | AC-6 |
| `policy.sensitive_action_on_star` | 1.16 | CC6.3 | AC-6(1) |
| `iam.escalation.passrole_createkey` | 1.16 / 1.20 | CC6.3 | AC-6(9) |
| `iam.principal.admin_access` | 1.16 | CC6.3 | AC-6(5) |
| `log.denied_sensitive_iam` | 4.x (monitoring) | CC7.2 | AU-6 |

A **Compliance page** renders each framework as a checklist with pass/fail counts, % compliant, and drill-down to the failing findings. The mapping lives in a single `compliance/mappings.py` table so it's auditable and extendable.

---

## 7. Findings Workflow & Collaboration

### 7.1 Status state machine

Finding status lives on `finding_group` (durable across runs). States and transitions:

```
        ┌──────────────────────────────────────────────────────┐
        │                                                      ▼
   ┌────────┐   assign/start   ┌──────────────┐  resolve  ┌──────────┐
   │  OPEN  │ ───────────────► │ INVESTIGATING│ ────────► │ RESOLVED │
   └────────┘                  └──────────────┘           └──────────┘
      │  │  ▲                        │  ▲                     │  │
      │  │  │ reopen (new evidence)  │  │ reopen              │  │ reopen
      │  │  └────────────────────────┴──┴─────────────────────┘  │
      │  │                                                        │
      │  └──── accept risk ──────► ┌───────────────┐ ◄────────────┘
      │                            │ ACCEPTED_RISK │
      └──── suppress ───────────►  └───────────────┘
                                   ┌───────────────┐
                                   │  SUPPRESSED   │  (auto-reopens on exception expiry)
                                   └───────────────┘
```

**Allowed transitions & who can trigger (see §10 for roles):**

| From | To | Allowed roles | Side effects |
|---|---|---|---|
| open | investigating | analyst, admin | requires assignee (self by default) |
| open | suppressed | analyst, admin | creates `finding_exception(kind=suppressed)` + reason |
| open | accepted_risk | admin | creates `finding_exception(kind=accepted_risk)` + reason + optional expiry |
| investigating | resolved | analyst, admin | records resolution note |
| investigating | open | analyst, admin | reopen |
| resolved | open | analyst, admin | reopen (auto on re-detection with changed evidence) |
| suppressed | open | analyst, admin | revokes exception |
| accepted_risk | open | admin | revokes exception |
| any | (auto) open | system | on exception expiry the scheduler reopens |

Every transition writes a `finding_status_history` row (from, to, actor, note, timestamp). Invalid transitions are rejected at the service layer (`WorkflowService.transition(group_id, to_status, actor, note)` raises `InvalidTransition`).

### 7.2 Assignment model

- A finding group has one `assignee_id` (nullable). Assigning is a distinct action from status change but often paired (assign -> auto-move to investigating is offered).
- "Assign to me" is the one-click default; a picker lists active `app_user`s.
- Assignment changes are recorded in `audit_event`. A "My findings" saved view filters `assignee_id = current_user`.

### 7.3 Comments

- Markdown comments on a finding group, rendered with a safe markdown renderer (bleach-sanitized).
- `@mention` autocompletes app users (stored as plain text mention tokens; notification is out of scope but the mention renders as a chip).
- Comments show on the finding detail drawer with author avatar (initials), timestamp, and edit/delete for the author or admin.

### 7.4 Suppression & accepted-risk (with expiry)

- **Suppressed** = "don't show me this, it's noise." **Accepted risk** = "we acknowledge and accept this." Both create a `finding_exception`.
- Optional `expires_at`. A daily APScheduler job (`expire_exceptions`) revokes expired exceptions and transitions the group back to `open`, writing history ("exception expired, auto-reopened"). This "re-surfacing" is a differentiator most hobby projects miss and reads as real security-ops thinking.
- Suppressed/accepted findings are excluded from the account posture score and hidden from default views but reachable via a "Show suppressed" toggle and an **Exceptions page** listing all active exceptions with expiry countdowns.

### 7.5 Ticketing / notification integration (abstracted)

A single `IntegrationTarget` abstraction with pluggable adapters so the demo shows the pattern without requiring real SaaS creds:

```python
class TicketAdapter(Protocol):
    def create_ticket(self, finding: FindingView) -> TicketRef: ...

# Implementations:
# - WebhookAdapter   -> POST JSON to a configured URL (works with any system)
# - JiraAdapter      -> stub that formats a Jira issue payload; if creds absent,
#                       logs + returns a fake JIRA-123 ref and shows a toast
# - SlackAdapter     -> stub that formats a Slack Block Kit message
```

"Create ticket" on a finding opens a small modal (target picker + editable title/body prefilled from the finding), calls the adapter, stores the returned `TicketRef` on the finding group (add `ticket_ref` column), and shows it as a linked chip on the finding. In demo mode everything is a well-formed stub with clear "simulated" labeling — honest and still demonstrative.

---

## 8. UX & Interaction Design (the "down to the smallest right-click" section)

This section is the differentiator. The target feel is a **dense, keyboard-driven, professional security console** — think Linear/Datadog, not a Bootstrap CRUD form.

### 8.1 Design system & layout shell

- **Design tokens** (CSS custom properties) for color, spacing, radius, typography. Two themes via `[data-theme="dark|light"]` on `<html>`; **dark is default**. Theme persists in `localStorage` and respects `prefers-color-scheme` on first visit.
- **Palette (dark):** near-black background `#0B0E14`, panel `#131722`, border `#232A36`, text `#E4E7EB`, muted `#8A94A6`. Severity colors: CRITICAL `#E5484D`, HIGH `#F76808`, MEDIUM `#F5A623`, LOW `#3E9BFF`, INFO/resolved `#30A46C`.
- **App shell:** left icon sidebar (Dashboard, Accounts, Findings, Graph, Compliance, Runs, Exceptions, Settings), a top bar (account switcher, global search, `Cmd+K` hint, theme toggle, user menu), and a main content area. Sidebar collapsible; state persisted.
- **Density toggle:** comfortable / compact row heights for the findings table.

### 8.2 Findings table — the core surface (full spec)

The findings table is where users live. It must be **virtualized** (render only visible rows) to handle thousands of findings smoothly.

**Columns (default order, all toggleable & reorderable):**

| Column | Sortable | Resizable | Hideable | Default |
|---|---|---|---|---|
| ☐ (select checkbox) | no | no | no | shown |
| Risk (0-100 badge) | yes | yes | no | shown |
| Severity (colored pill) | yes | yes | no | shown |
| Status (pill) | yes | yes | no | shown |
| Title | yes | yes | no | shown |
| Principal | yes | yes | yes | shown |
| Category | yes | yes | yes | shown |
| Compliance (tag chips) | no | yes | yes | shown |
| Assignee (avatar) | yes | yes | yes | shown |
| First seen | yes | yes | yes | hidden |
| Last seen | yes | yes | yes | shown |
| Age (days) | yes | yes | yes | hidden |
| Check ID | yes | yes | yes | hidden |
| ⋯ (row actions) | no | no | no | shown |

**Behaviors:**

- **Sorting:** click header to sort; shift-click for multi-column sort; sort indicator arrow; sort state encoded in URL query (`?sort=-risk,severity`) so it's shareable and htmx-refreshable.
- **Resizing:** drag column border; widths persist per user in the active saved view.
- **Show/hide & reorder:** a "Columns" dropdown (checkbox list + drag handles). Persisted to saved view.
- **Row selection:** checkbox column; click-row selects; shift-click range select; `Ctrl/Cmd+click` toggles; a header checkbox for select-all-in-view with a "Select all N matching filter" affordance banner when filtered.
- **Filtering:** a filter bar with facet chips (Severity, Status, Category, Assignee, Compliance framework, Has exception) plus a free-text search over title/principal. Filters combine (AND across facets, OR within a facet). Filter state in URL.
- **Density & wrap:** compact/comfortable toggle; long titles ellipsize with tooltip.
- **Row click:** opens the **Finding Detail drawer** (slides from right) — does not navigate away, preserving table scroll position.
- **Inline quick actions** on hover at row end: assign-to-me, change status, open menu.
- **Empty/loading/error states** per §8.7.

### 8.3 Right-click context menu — per single row

Right-clicking a finding row (or clicking the ⋯ button) opens a context menu. Exact contents, in order:

```
View evidence / details            (opens detail drawer, focuses Evidence tab)
Open principal in graph            (jumps to blast-radius graph focused on principal)
──────────────────────────────
Change status ▸
    → Mark Investigating
    → Mark Resolved
    → Reopen
Assign ▸
    → Assign to me
    → Assign to…            (submenu with user search)
──────────────────────────────
Suppress finding…                  (opens suppress modal: reason + optional expiry)
Accept risk…                       (admin only; reason + expiry)
Re-run this check                  (enqueues a targeted single-check re-scan)
Create ticket…                     (integration modal)
──────────────────────────────
Copy ▸
    → Copy as Markdown             (formatted finding block to clipboard)
    → Copy as JSON                 (raw finding object)
    → Copy remediation snippet
    → Copy finding link            (deep link URL)
──────────────────────────────
Add comment…                       (opens drawer, focuses comment box)
```

Menu items disable/hide based on role and current status (e.g., "Mark Resolved" hidden if already resolved; "Accept risk" hidden for non-admins). The menu is keyboard-navigable (arrow keys, Enter, Esc) and closes on outside click / Esc.

### 8.4 Right-click / bulk-action menu — multi-select

When 2+ rows are selected, a **bulk action bar** docks at the top of the table ("N selected · Clear") and the same right-click gesture yields the bulk menu:

```
Change status for N findings ▸   (Investigating / Resolved / Reopen)
Assign N findings ▸              (to me / to…)
Suppress N findings…             (single reason + expiry applied to all)
Accept risk for N findings…      (admin only)
Add compliance/label…            (bulk tag — optional)
Re-run checks for N findings
──────────────────────────────
Export selected ▸                (CSV / JSON / Markdown)
Copy N as JSON
──────────────────────────────
Clear selection
```

All bulk mutations run through the service layer transactionally and write one `audit_event` plus per-group `finding_status_history` rows. A toast reports "Updated 14 findings" with an **Undo** (implemented by reversing the recorded transitions within a short window).

### 8.5 Command palette (`Cmd/Ctrl+K`)

A fuzzy-searchable palette (Alpine component) with grouped actions:

- **Navigate:** Go to Dashboard / Findings / Graph / Compliance / Runs / Accounts / Exceptions / Settings.
- **Actions:** Run scan (account picker), Connect account, Compare last two runs (open diff), Create saved view, Toggle theme, Toggle density.
- **Search findings:** typing filters findings by title/principal; selecting opens that finding's drawer.
- **Recent:** last viewed findings/runs.
- Each entry shows its keyboard shortcut if one exists. Arrow keys + Enter; Esc closes. Fuzzy match highlights.

### 8.6 Keyboard shortcuts (global + table)

| Key | Context | Action |
|---|---|---|
| `Cmd/Ctrl+K` | global | Open command palette |
| `/` | global | Focus search box |
| `g` then `d` | global | Go to Dashboard |
| `g` then `f` | global | Go to Findings |
| `g` then `r` | global | Go to Runs |
| `g` then `c` | global | Go to Compliance |
| `j` / `k` | findings table | Move selection down / up |
| `x` | findings table | Toggle row selection |
| `Shift+j/k` | findings table | Extend selection |
| `Enter` / `o` | findings table | Open focused finding drawer |
| `e` | focused/selected | Mark Resolved (e = "end/resolve") |
| `i` | focused/selected | Mark Investigating |
| `a` | focused/selected | Assign to me |
| `s` | focused/selected | Suppress (opens modal) |
| `c` | focused/selected | Add comment |
| `.` | focused row | Open context menu at row |
| `[` / `]` | drawer open | Previous / next finding |
| `t` | global | Toggle theme |
| `?` | global | Open shortcut cheat-sheet overlay |
| `Esc` | any | Close drawer/menu/palette |

A `?` overlay documents all shortcuts (portfolio polish signal).

### 8.7 Empty / loading / error states

- **Loading table:** skeleton rows (shimmer), not a spinner, so layout doesn't jump.
- **Scan running:** progress card with stage text + percentage + animated bar, streamed via SSE; findings table shows "Scan in progress…" with a live count that increments as findings land.
- **Empty (no findings):** celebratory "No open findings — posture score A" state with illustration, not a blank table.
- **Empty (filtered to nothing):** "No findings match these filters" + "Clear filters" button.
- **Error (scan failed):** red banner with the error message, a "Retry scan" button, and a link to the run's logs.
- **No account connected:** first-run empty state with a big "Connect your first account" CTA opening the wizard.

### 8.8 Finding detail drawer

Slide-over from the right (60% width, resizable), tabbed:

- **Overview:** title, severity, risk score gauge, status control, assignee, principal link, compliance tags, first/last seen, age.
- **Evidence:** the structured proof — matched log lines (monospace, highlighted), the offending policy statement (JSON, syntax-highlighted), computed metrics (e.g., "reachable sensitive actions: 14").
- **Remediation:** human recommendation + copy-paste snippet (CLI/policy JSON) with a copy button.
- **Graph:** mini blast-radius graph focused on the principal.
- **Activity:** the status history timeline + comments thread + assignment changes (unified audit trail).
- Footer: primary actions (status transition buttons), overflow menu mirroring the context menu. `[`/`]` navigate between findings without closing.

### 8.9 Run diff view

- Entry points: Runs page "Compare" button, command palette, dashboard "since last scan" strip.
- Layout: a run-picker header (Run A ▾ vs Run B ▾, defaults to previous vs latest) + summary banner (`+5 new · -3 resolved · 12 unchanged · net risk +18 · score 74 -> 68`).
- Three-column board: **New** (red header), **Changed** (amber, shows deltas like severity ↑ or evidence count 12->40), **Resolved** (green). Each card is a compact finding row; clicking opens the drawer.
- A small **score trend sparkline** across all runs sits above.

### 8.10 Saved views

- Save the current filter + sort + visible/ordered/resized columns + density as a named view (private or shared).
- Views appear as tabs/pills above the table ("All Open", "Critical", "My Findings", "CIS Failures", "Suppressed"). Ship 4-5 sensible defaults seeded on install.
- A view can be set as personal default (loads on Findings page open).

### 8.11 Full page-by-page inventory

Beyond the 4 pages that exist today, the app comprises:

| Page / route | Purpose / contents |
|---|---|
| `/` Landing | Marketing hero, feature highlights, screenshots, "Launch demo" CTA, GitHub link. (Evolve existing.) |
| `/login` | Auth form; demo-credential hint box. |
| `/dashboard` | Account posture gauge + grade, severity/category donut, compliance summary, "since last scan" strip, top-10 riskiest findings, riskiest principals, recent runs, run-scan button. |
| `/accounts` | List of connected accounts (cards: name, provider, last scan, score, schedule badge). "+ Connect Account" wizard. |
| `/accounts/{id}` | Account detail: runs list, schedule config, thresholds, danger-zone (delete). |
| `/findings` | The core virtualized findings table (§8.2) with saved views, filters, bulk actions. |
| `/findings/{group_id}` | Deep-link that opens the detail drawer over the table (or standalone if direct). |
| `/graph` | Full blast-radius graph explorer; principal search, filters (sensitive-only, show escalation paths), node detail panel. |
| `/principals` | Table of principals with blast-radius score, reachable actions, MFA, key age; drill to graph. |
| `/compliance` | Per-framework checklists (CIS/SOC2/NIST), pass/fail %, drill-down to failing findings, export. |
| `/runs` | Run history (status, duration, findings counts, score, trigger); Compare button; download JSON/CSV. |
| `/runs/{id}` | Single run detail + live progress if running. |
| `/runs/diff?a=&b=` | Diff view (§8.9). |
| `/exceptions` | All active suppressions/accepted-risk with reason, creator, expiry countdown, revoke action. |
| `/checks` | Catalog of all registered checks (like Prowler's check list): id, category, severity, compliance, description. |
| `/settings` | App settings: users & roles (admin), integrations (webhook/Jira/Slack), theme default, danger zone. |
| `/settings/users` | User admin (admin only): invite, set role, deactivate. |
| `/api/docs` | Swagger UI / Redoc for the OpenAPI spec. |
| `/profile` | Current user: name, password change, personal defaults. |

### 8.12 Responsive behavior

- Primary target is desktop (this is a data-dense console). Below ~1024px: sidebar collapses to icons; findings table drops low-priority columns and offers a card layout; drawers go full-screen. The landing page is fully responsive. Graph view shows a "best on desktop" hint on small screens.

---

## 9. API Design

A versioned JSON API (`/api/v1`) sits alongside the HTML app, documented via OpenAPI (flask-smorest -> Swagger UI at `/api/docs`). The HTML app uses htmx against server-rendered partials; the JSON API is for programmatic use and to demonstrate API design competence. Auth for the API uses a bearer token (see §10); the HTML app uses session cookies.

**Conventions:** JSON bodies, ISO-8601 UTC timestamps, cursor/offset pagination (`?limit=&offset=` + `X-Total-Count`), consistent error envelope `{"error": {"code": "...", "message": "...", "details": {...}}}`, RFC-ish status codes (400/401/403/404/409/422/500).

### 9.1 Endpoint inventory

| Method | Path | Purpose | Request | Response |
|---|---|---|---|---|
| POST | `/api/v1/auth/login` | Obtain token | `{email,password}` | `{token, user}` |
| POST | `/api/v1/auth/logout` | Invalidate token | — | `204` |
| GET | `/api/v1/me` | Current user | — | `{id,email,role,...}` |
| GET | `/api/v1/accounts` | List accounts | — | `[Account]` |
| POST | `/api/v1/accounts` | Create/connect account | `{name,provider,source_type,source_config}` | `Account` |
| GET | `/api/v1/accounts/{id}` | Account detail | — | `Account` |
| DELETE | `/api/v1/accounts/{id}` | Delete account | — | `204` |
| POST | `/api/v1/accounts/{id}/scans` | Enqueue scan | `{thresholds?}` | `202 {run_id, status}` |
| GET | `/api/v1/runs` | List runs (filter by account) | `?account_id=` | `[Run]` |
| GET | `/api/v1/runs/{id}` | Run status/summary | — | `Run + summary` |
| POST | `/api/v1/runs/{id}/cancel` | Cancel a running scan | — | `202` |
| GET | `/api/v1/runs/{id}/events` | **SSE** progress stream | — | `text/event-stream` |
| GET | `/api/v1/runs/{id}/findings` | Findings for a run | filter/sort/paginate params | `[Finding]` |
| GET | `/api/v1/runs/diff` | Diff two runs | `?a=&b=` | `RunDiff` |
| GET | `/api/v1/findings` | Query findings (latest run per account by default) | rich filters | `[Finding]` |
| GET | `/api/v1/findings/{group_id}` | Finding detail incl. history/comments | — | `FindingDetail` |
| POST | `/api/v1/findings/{group_id}/transition` | Status change | `{to_status, note}` | `FindingDetail` |
| POST | `/api/v1/findings/{group_id}/assign` | Assign | `{assignee_id}` | `FindingDetail` |
| POST | `/api/v1/findings/{group_id}/comments` | Add comment | `{body}` | `Comment` |
| POST | `/api/v1/findings/{group_id}/exceptions` | Suppress/accept risk | `{kind, reason, expires_at?}` | `Exception` |
| DELETE | `/api/v1/findings/{group_id}/exceptions/{id}` | Revoke exception | — | `204` |
| POST | `/api/v1/findings/{group_id}/ticket` | Create ticket | `{target, title, body}` | `{ticket_ref}` |
| POST | `/api/v1/findings/bulk` | Bulk action | `{group_ids[], action, params}` | `{updated: N}` |
| GET | `/api/v1/principals` | Principals w/ blast scores | `?run_id=` | `[Principal]` |
| GET | `/api/v1/principals/{uid}/graph` | Graph nodes/edges for principal | `?run_id=` | `{nodes, edges}` |
| GET | `/api/v1/compliance` | Framework summaries | `?run_id=&framework=` | `[FrameworkSummary]` |
| GET | `/api/v1/checks` | Check catalog | — | `[CheckMeta]` |
| GET | `/api/v1/saved-views` / POST | List/create saved views | — / `{name,scope,config}` | `[SavedView]` |
| GET/POST/PATCH/DELETE | `/api/v1/schedules` | CRUD recurring scans | `{account_id,cron,thresholds}` | `Schedule` |
| GET/POST/PATCH | `/api/v1/users` | User admin (admin only) | — | `[AppUser]` |
| GET | `/api/v1/runs/{id}/report.json` / `.csv` | Download artifacts | — | file |

### 9.2 Example payloads

```jsonc
// GET /api/v1/findings/{group_id}
{
  "group_id": 812,
  "check_id": "iam.escalation.passrole_createkey",
  "title": "Privilege escalation: intern can assume admin role via PassRole",
  "severity": "CRITICAL",
  "status": "investigating",
  "risk_score": 94,
  "principal_uid": "arn:aws:iam::1234:user/intern",
  "assignee": {"id": 3, "name": "Priya S."},
  "compliance_tags": ["CIS_AWS_1.4:1.16", "NIST:AC-6(9)"],
  "evidence": {
    "escalation_path": ["intern", "iam:PassRole", "CI-Deploy", "AdministratorAccess"],
    "statements": [ /* offending policy statement JSON */ ]
  },
  "remediation": "Remove iam:PassRole from the intern policy or scope it to non-privileged roles.",
  "remediation_snippet": "{ \"Effect\": \"Deny\", \"Action\": \"iam:PassRole\", ... }",
  "history": [ {"to":"open","at":"..."}, {"to":"investigating","actor":"Priya S.","at":"..."} ],
  "comments": [ {"author":"Priya S.","body":"Confirmed with team.","at":"..."} ]
}
```

---

## 10. Auth & Authorization Design

### 10.1 Authentication

- **HTML app:** session cookies via **Flask-Login**. Passwords hashed with **argon2** (via `argon2-cffi`) or bcrypt. Login form at `/login`, CSRF-protected (Flask-WTF). Session timeout + "remember me".
- **JSON API:** bearer token. On `POST /api/v1/auth/login`, issue a signed token (itsdangerous-signed or JWT via PyJWT) with `user_id`, `role`, `exp`. Sent as `Authorization: Bearer <token>`. Keep it simple — signed tokens, no refresh-token complexity for a portfolio scope; document the choice.
- **Seeded demo accounts:** `admin@demo.local` / `analyst@demo.local` / `viewer@demo.local` (password shown on the login page for the live demo). This lets a recruiter log in instantly.

### 10.2 Roles & permissions (RBAC)

Three roles; enforced by a `@require_role(...)` decorator on routes and re-checked in the service layer.

| Capability | admin | analyst | read_only |
|---|:---:|:---:|:---:|
| View dashboards/findings/graph/compliance | ✅ | ✅ | ✅ |
| Export CSV/JSON | ✅ | ✅ | ✅ |
| Run / cancel scans | ✅ | ✅ | ❌ |
| Connect / delete accounts | ✅ | ❌ | ❌ |
| Change finding status / assign / comment | ✅ | ✅ | ❌ |
| Suppress finding | ✅ | ✅ | ❌ |
| Accept risk (create accepted-risk exception) | ✅ | ❌ | ❌ |
| Create tickets | ✅ | ✅ | ❌ |
| Manage schedules | ✅ | ✅ | ❌ |
| Manage users / integrations / settings | ✅ | ❌ | ❌ |

UI hides/disables actions the current role can't perform; the server still enforces (defense in depth). Unauthorized attempts return `403` and write an `audit_event`.

---

## 11. Background Jobs & Scheduling

### 11.1 Job lifecycle

1. **Enqueue:** `ScanService.enqueue_scan(account_id, thresholds, trigger, actor)` creates a `run` (`status=queued`) and enqueues `run_scan_job(run_id)` on the RQ default queue. Returns immediately (`202`).
2. **Execute (worker):** `run_scan_job` sets `status=ingesting`, runs the adapter, then `status=analyzing`, runs the engine, persists results, writes the report artifact, sets `status=completed` + `duration_ms` + `composite_score`. Wrapped in try/except: on failure sets `status=failed` + `error_message` and re-raises for RQ's failed-job registry.
3. **Progress:** a `ProgressReporter` writes `progress_pct` + `progress_stage` to both the `run` row (durable) and a Redis key, and publishes to a Redis pub/sub channel `run:{id}:progress`.

### 11.2 Progress to the UI (SSE + polling fallback)

- `GET /api/v1/runs/{id}/events` is an SSE endpoint subscribed to `run:{id}:progress`; it streams `event: progress` messages (`{pct, stage}`) and a final `event: done`. The scan page and dashboard progress card consume it.
- **Fallback:** if SSE isn't available (some proxies), the UI polls `GET /api/v1/runs/{id}` every 1.5s until terminal status. htmx `hx-trigger="every 1500ms"` on the progress partial makes this trivial.

### 11.3 Retry & failure handling

- Transient ingestion errors (e.g., moto seed race) retry up to 2x with backoff via RQ's `Retry(max=2)`.
- Non-transient failures land in RQ's failed registry and surface in the run detail page with the traceback (dev) or a friendly message (prod) plus a "Retry scan" button that enqueues a fresh run.
- A cancel flag (`run.status=canceled` + a Redis `cancel:{run_id}` key checked between stages) supports `POST /runs/{id}/cancel`.

### 11.4 Scheduled recurring scans

- **APScheduler** `BackgroundScheduler` runs in the **worker** process (single instance) to avoid duplicate firing across Gunicorn web workers.
- On startup it loads enabled `schedule` rows and registers cron jobs; a lightweight watcher re-syncs when schedules change (or just reload on schedule CRUD via a Redis pub/sub signal).
- Each fire acquires a Redis lock, enqueues a scan (`trigger=scheduled`), updates `last_run_at`/`next_run_at`.
- The daily `expire_exceptions` maintenance job (also APScheduler) reopens expired suppressions/accepted-risk.

---

## 12. Testing Strategy

Testing is a first-class portfolio signal. Target **>85% coverage on core logic** (parser, rule engine, risk/graph), reported via a Codecov (or CI-artifact) badge.

### 12.1 Highest-risk targets (test these hardest)

1. **Regex log parser** — both the plaintext regex format and the JSON/CloudTrail path.
   - Table-driven unit tests over a fixture corpus (`tests/fixtures/logs/`) with known expected parses (timestamps, principal, ip, outcome, event_name).
   - **Property-based tests (Hypothesis):** generate synthetic-but-valid log lines and assert the parser never crashes, always returns a well-formed event or a clean "unparsed" marker, and round-trips fields. This catches the classic regex brittleness that breaks hobby tools.
   - Malformed/adversarial inputs: truncated lines, unicode, injection-y strings, huge lines, empty files, mixed formats in one file.
2. **Rule engine / checks** — each check gets a dedicated test with a crafted `CheckContext` fixture proving it fires when it should and stays silent when it shouldn't (positive + negative). Threshold boundary tests (e.g., key age exactly at the limit).
3. **Risk scoring** — deterministic inputs -> expected score bands; monotonicity properties (more sensitive reachable actions never lowers blast score).
4. **Graph / blast radius** — small hand-built graphs with known escalation paths; assert path detection and reachability counts.
5. **Fingerprint stability** — same logical issue across two runs -> identical fingerprint; different resource -> different fingerprint.
6. **Workflow state machine** — every allowed transition succeeds, every disallowed transition raises, history rows written, RBAC enforced.

### 12.2 Integration tests

- **API tests** (pytest + Flask test client): auth flow, enqueue scan (with RQ in synchronous/`is_async=False` mode or fakeredis), fetch findings, transitions, bulk actions, diff, RBAC 403s.
- **Ingestion tests:** run `MotoAwsIngestionAdapter` against a moto mock seeded with a tiny fixture org; assert normalized dataset shape.
- **End-to-end smoke:** seed -> scan -> assert expected number/severity of findings from the known seed (a "golden" assertion that the seeded escalation path produces the CRITICAL finding).

### 12.3 Tooling & CI hookup

- `pytest`, `pytest-cov`, `hypothesis`, `factory_boy` (model factories), `freezegun` (time), `fakeredis` (queue), `responses` (REST adapter).
- `pytest -q --cov=app --cov-report=term-missing --cov-fail-under=80` in CI.
- Fast unit suite separated from slower integration suite via markers (`-m "not integration"` for the quick loop).

---

## 13. DevEx & Repo Polish Plan

### 13.1 Docker / docker-compose (one-command demo)

`docker compose up` must yield a fully seeded, logged-in-able app in under ~2 minutes.

**Services:**

```yaml
services:
  web:      # Flask + Gunicorn, serves UI + API, waits for redis/db
  worker:   # RQ worker + APScheduler (scans, schedules, exception expiry)
  redis:    # queue + SSE pub/sub + cache
  db:       # optional postgres; omit to use bundled SQLite volume
  seed:     # one-shot: runs migrations + seeds demo account, users, moto org, sample run
```

- `seed` runs `alembic upgrade head`, creates the three demo users, connects the "Acme Corp" moto account, and executes one initial scan so the app opens with data already present (recruiters see findings immediately, not an empty shell).
- A single `.env.example` documents all config. `make demo` / `just demo` wrapper for niceness.
- Multi-stage Dockerfile (slim base, non-root user, pinned deps via `requirements.txt`/`pyproject.toml`).

### 13.2 GitHub Actions CI

`.github/workflows/ci.yml`:

1. **Setup** — checkout, set up Python 3.11, cache pip.
2. **Lint & format check** — `ruff check .` and `ruff format --check .`.
3. **Type check** — `mypy app/`.
4. **Test** — `pytest --cov --cov-fail-under=80`, upload coverage.
5. **Build** — `docker build` to prove the image builds.
6. Badges in README: CI status, coverage, license, Python version.

Optional second workflow: build & push image on tag; a `docs`/link-check job.

### 13.3 Lint / format / type tooling

- **ruff** for lint + format (replaces black+flake8+isort — modern, fast, one tool).
- **mypy** in non-strict-but-meaningful mode on `app/` (strict on core logic modules).
- **pre-commit** hooks: ruff, mypy, end-of-file/trailing-whitespace, check-yaml, detect-secrets.

### 13.4 README structure

```
# IAM Sentinel
> one-line positioning (from §2) + badges (CI, coverage, license)

[ Hero screenshot or animated GIF of the findings table + graph ]

## Why / What it demonstrates
## Features (with small screenshots per marquee feature: graph, diff, workflow, compliance)
## Architecture (embedded architecture diagram from §3)
## Quickstart (docker compose up — 3 lines)
## Demo credentials
## Simulated cloud note (honest explanation of moto)
## Tech stack
## Screenshots gallery / GIF
## Testing & CI
## Roadmap (link to phases)
## License
```

- Put a real **architecture diagram** (export the §3 ASCII to a clean diagram via Excalidraw/Mermaid) and 4-6 screenshots + one GIF (findings table interaction / running a scan / graph) in `docs/img/`.

### 13.5 Repo hygiene files

- **LICENSE** — MIT (permissive, expected for a portfolio piece).
- **CHANGELOG.md** — Keep a Changelog format, versioned per phase.
- **CONTRIBUTING.md** — dev setup, run tests, code style, branch/PR conventions.
- **CODE_OF_CONDUCT.md** (optional), **SECURITY.md** (nice ironic touch for a security tool), issue/PR templates, a `docs/ARCHITECTURE.md` (condensed from this spec).

### 13.6 Live demo deployment (free tier)

- Target **Render**, **Railway**, or **Fly.io** free/hobby tier. Web + worker + Redis; SQLite on a small persistent volume (or the platform's free Postgres).
- Since it's all simulated (no cloud creds), the demo is safe to expose publicly. Seed on deploy. Put the URL + demo creds at the top of the README. A read-only demo user prevents griefing of shared state; optionally reset seed nightly via a scheduled job.

---

## 14. Phased Build Roadmap

Each phase ends at a **demoable, self-contained milestone** so the user can stop anywhere and still have something impressive. Hand these to Claude Code one phase at a time.

### Phase 0 — Foundation & refactor (backend spine)
**Deliver:** SQLAlchemy + Alembic introduced; existing CSV/JSON/log/rule logic refactored behind the service layer and `IngestionAdapter`/rule-registry interfaces (behavior-preserving); new data model migrated in; ruff/mypy/pytest wired; first unit tests for the log parser and 3-4 checks; pre-commit.
**Demoable:** existing CLI + Flask still works, now on the new schema, green test suite and lint.
**Why first:** everything else builds on the registry, adapters, and schema.

### Phase 1 — Findings workflow + core UX shell
**Deliver:** app shell (sidebar/topbar/theme tokens, dark/light), the virtualized findings table (§8.2) with sorting/filtering/columns/saved views, the finding detail drawer, status state machine + audit trail + comments + assignment, suppression/accepted-risk with expiry, the right-click context menu (single + bulk), command palette, keyboard shortcuts, empty/loading/error states.
**Demoable:** upload sample data -> triage findings end to end with a real workflow and slick interactions. This alone already beats most hobby projects.

### Phase 2 — Simulated cloud ingestion + scheduling + diff
**Deliver:** moto seed org + `MotoAwsIngestionAdapter`; "Connect Account" wizard; RQ+Redis background scans with SSE progress; APScheduler recurring scans + exception expiry; run-to-run diff computation + diff view; run history upgrades.
**Demoable:** "Connect account" -> watch a live progress bar -> scan completes -> compare against previous run. The commercial-feel jump.

### Phase 3 — Analysis engine upgrades (the "wow")
**Deliver:** permission graph + blast-radius scoring; escalation-path detection + graph view (Cytoscape); least-privilege used-vs-granted engine + suggested policies; composite risk scoring + account posture gauge/grade + score trend; compliance mapping + compliance page + checks catalog.
**Demoable:** blast-radius graph, "this intern can become admin" escalation finding, least-privilege recommendation, CIS/SOC2/NIST compliance dashboard. This is the marquee recruiter moment.

### Phase 4 — API, auth, collaboration integrations
**Deliver:** Flask-Login auth + 3-role RBAC + seeded demo users; OpenAPI-documented `/api/v1` with Swagger UI; bearer-token API auth; ticket/webhook/Jira/Slack integration abstraction + "Create ticket" flow; user admin & settings pages.
**Demoable:** log in as different roles, hit the documented API, create a (simulated) ticket from a finding.

### Phase 5 — Polish, CI, docs, deploy
**Deliver:** docker-compose one-command demo with seed service; GitHub Actions CI (lint+type+test+build) + badges; coverage to target; README with screenshots/GIF/architecture diagram; CHANGELOG/LICENSE/CONTRIBUTING/SECURITY; live free-tier deployment.
**Demoable:** the GitHub repo itself — green badges, gorgeous README, one-command run, live link.

**Suggested phase ordering rationale:** workflow+UX (Phase 1) before cloud ingestion (Phase 2) so there's an impressive interactive artifact early; the graph/analysis "wow" (Phase 3) is high-effort/high-reward and sits in the middle so it's not skipped; auth/API/polish trail because they're additive rather than foundational to the demo story.

---

## 15. Risks & Scope Management

### 15.1 Where the user will over-scope / burn out

| Trap | Mitigation |
|---|---|
| **Rewriting to React** | Explicitly forbidden here — htmx + Alpine delivers the feel at a fraction of the cost. Don't. |
| **Building 300 checks like Prowler** | 20-30 well-crafted, well-tested, compliance-mapped checks read as more thoughtful than 300 shallow ones. Quality over count. |
| **Perfecting the graph algorithm** | Blast radius + escalation-path detection on a curated sensitive-action list is enough. Don't attempt a full IAM policy evaluation engine (condition keys, resource-policy intersections) — note it as "future work." |
| **Real multi-cloud** | AWS-via-moto only. Azure/GCP are greyed "coming soon" cards. |
| **Real Jira/Slack OAuth** | Abstraction + stubs with honest "simulated" labels. |
| **WebSockets, microservices, k8s** | SSE + a two-service compose is plenty. Resist infra sprawl. |
| **Chasing 100% coverage everywhere** | Target 85% on core logic; don't unit-test Jinja templates. |

### 15.2 The minimum "still impressive" cut line

If time is tight, ship **Phase 0 + Phase 1 + Phase 3-lite + Phase 5**, in this reduced form:

- Phase 0 (foundation, tests, lint) — **non-negotiable**; it's the engineering-credibility layer.
- Phase 1 (workflow + UX shell + findings table + context menus + command palette) — **the interaction depth the user explicitly wants**; this is the visible differentiator.
- A **thin slice of Phase 3**: composite risk scoring + account posture grade + a basic blast-radius graph + CIS compliance mapping. Even a modest graph screenshot is the single most "commercial-looking" asset.
- Phase 5 (docker one-command, CI badges, README with screenshots/GIF) — **non-negotiable**; the repo's first impression is the README and the green badges.

Defer if needed: moto ingestion (fall back to the existing file upload + a pre-seeded sample account), scheduling, the full API/RBAC, and ticket integrations. The app is still portfolio-defining with just: a beautiful interactive findings console + workflow + risk scoring + a blast-radius graph + a one-command demo + a polished repo.

### 15.3 Sequencing advice for the AI coding agent

- Do Phase 0 fully and get tests green **before** any UI work — a stable service layer prevents rework.
- Build the findings table and drawer against **static seed data** first, then wire background scans; don't block UX progress on the worker.
- Land the moto seed org early even if ingestion comes later — a realistic dataset makes every screenshot better.
- Keep each check's compliance tags and remediation snippet populated from day one; retrofitting them across 25 checks later is tedious.
- Commit per feature with meaningful messages; the git history is part of the portfolio.

---

*End of specification.*
