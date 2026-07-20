# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions track the build phases.

## [Unreleased] — Phase 5: DevEx & repo polish (in progress)

### Added
- Committed Playwright E2E suite (`tests/e2e/`, own README): login/logout +
  RBAC gating across all three seeded demo roles, one full findings-workflow
  cycle (transition/comment/assign/suppress), the run-to-run diff view, and
  blast-radius graph rendering (verified via the real Cytoscape instance, not
  just markup presence) — the handful of flows most likely to actually catch
  a browser-level regression, not a recreation of every ad hoc verification
  script run by hand across every phase. Wired as its own `e2e` CI job,
  independent of `quality`: seeds a scratch DB (two moto scans, so the diff/
  graph views have real drift/escalation data to render), backgrounds the
  real Flask app, polls `/healthz`, then runs the suite against it over HTTP
  only — no route-internal shortcuts.

### Fixed
- CI workflow's push trigger targeted a `main` branch that doesn't exist in
  this repo (only `master` does) — CI had never actually run on a push here.
- CloudTrail activity classification: only the literal outcome `"denied"`
  excluded an event from counting as "used" by the least-privilege engine;
  failed/unknown-outcome events counted as used. Flipped to an allowlist
  (only a confirmed `"success"` counts) — paired with a fix to a related bug
  where an ordinary success-shaped CloudTrail record (no `errorCode`, no
  `responseElements`) was resolving to the literal string `"none"` instead
  of `"success"`, which would have made the allowlist change break every
  genuinely-successful action.
- `TrustWildcardPrincipalCheck` didn't require `Effect: Allow` or
  `Action: sts:AssumeRole` before flagging a public trust principal (a
  `Deny` statement or an unrelated action could false-positive), and missed
  list-valued wildcards like `{"AWS": ["*", ...]}`. Consolidated onto the
  same `is_assume_role_statement()` predicate the permission graph already
  used correctly, closing off the class of two-divergent-implementations
  bug that caused a real regression in Phase 3 Slice 1.
- The least-privilege engine's generated policy dropped `Deny`, `Condition`,
  `NotAction`, and `NotResource` forms from the source policy, which could
  make a "least privilege" suggestion broader than the original in effect.
  It now refuses to generate a suggested policy when any of those forms are
  present, rather than silently emitting a simplified-and-possibly-unsafe
  one; the blast-radius graph and least-privilege UI now disclose that this
  is a structural/heuristic model (Allow-statement grants only — no Deny,
  Condition, resource-policy intersection, permission boundary, or SCP
  evaluation), not full IAM policy evaluation.
- `pol.resources()` returned a `NotResource` statement's *excluded* resource
  list as if it were the *granted* one — a semantic inversion that made
  `sensitive_action_on_star` and `overly_broad_resource` miss genuinely-broad
  grants scoped by `NotResource` instead of `Resource: "*"`.
- Ticket-notification links sent to external integrations (webhook/Jira/Slack)
  were built from the incoming request's `Host` header, making them
  poisonable by a spoofed Host on an unauthenticated-adjacent path. A new
  optional `PUBLIC_BASE_URL` setting pins the external base URL when set;
  unset (dev/demo default) keeps deriving from the request, unchanged.
- The webhook integration adapter POSTed to any admin-configured URL with no
  destination validation — an SSRF risk against loopback/internal/cloud-
  metadata addresses, worse in a public deployment where the admin login is
  shared. `app/integrations/net_safety.py` now validates scheme/credentials,
  resolves the host once, rejects unsafe resolved addresses (loopback,
  private, link-local, reserved, multicast, and their IPv4-mapped IPv6
  forms), and pins the outbound connection to that validated IP so a second,
  different DNS answer can't be substituted at connect time.
- `SECRET_KEY` signed both the Flask session cookie and API JWTs, and the
  dev default was accepted at any startup, including a hypothetical
  production one. New `JWT_SECRET_KEY` setting (falls back to `SECRET_KEY`
  when unset, unchanged default behavior) plus `Settings.validate()`, which
  fails closed when `ENVIRONMENT=production` and either key is still the dev
  default, too short, or the two are identical.
- Public-demo hardening: a new `PUBLIC_MODE` setting clamps every capability
  above `read_only` to always-denied inside `rbac.at_least()` — the single
  choke point every enforcement path (route decorators, the API's
  `require_api_role`, and the service-layer `accept-risk`/`connect-account`
  re-checks) already calls, so turning this on protects all of them at once
  rather than needing a matching change at each call site.
- `user_service.update_role()`/`set_active()`'s last-active-admin lockout
  read the active-admin count and acted on it as two separate steps, with no
  lock — two concurrent requests could each read "another admin is still
  active" before either committed and both proceed, leaving zero active
  admins. Added `_lock_active_admins()`: `BEGIN IMMEDIATE` on SQLite,
  `SELECT ... FOR UPDATE` on Postgres, run before the count is read.
- `enqueue_scan()` didn't handle the job queue itself rejecting a submission
  (pool exhausted/shut down) — the Run stayed stuck `queued` forever, since
  nothing would ever call `execute_scan` to move it out of that state. The
  submission is now wrapped in `try`/`except`: on failure the Run is marked
  `failed` with the error recorded, mirroring `execute_scan`'s own
  record-then-raise shape.
- `ticket_service.create_ticket()` had no guard against being called twice
  for the same finding group — a retry (double-click, a client timeout on a
  request that actually succeeded server-side) would call the adapter again,
  creating a genuine second ticket in the external system, and silently
  overwrite `group.ticket_ref` with the new one, orphaning the first. Now
  rejects with `TicketError` when `group.ticket_ref` is already set.
- Suppress/accept-risk on the finding drawer silently stopped working
  whenever it followed any prior transition or assignment in the same
  drawer session — found by the new E2E suite's workflow-cycle test, not
  previously caught since no prior Playwright pass had chained those
  actions together. Root cause: htmx 2.0.4 corrupts a `<form>`'s element
  association (`.form`/`closest('form')` on its descendants silently
  becomes null, so its submit button stops firing) when an `hx-swap-oob`
  element precedes that `<form>` in the same response — confirmed via a
  minimal reproduction using only the vendored `htmx.min.js`, no Alpine, no
  rest of the app. `finding_drawer.html`'s suppress/accept-risk forms sit in
  the footer, and most mutations (transition, assign) render their OOB
  row-sync block *before* that footer. Fixed by moving the OOB blocks to
  the end of the template — a plain reordering, no behavior change to what
  gets swapped where.

### Changed
- Moved Flask-Login, Flask-WTF, argon2-cffi, email-validator, APScheduler,
  flask-smorest, marshmallow, and PyJWT from the `api`/`jobs` optional
  extras (plus a parallel copy kept in `dev`) into core `dependencies` — the
  web app (`app.web.create_app()`, the actual product surface since Phase 1)
  imports all of them unconditionally, so a bare `pip install .` with no
  extras was broken. `cloud` (boto3/moto) and `graph` (networkx) stay true
  optional extras — both are `find_spec()`-guarded in code and degrade
  gracefully when absent; `jobs` (rq/redis/fakeredis) stays declared-but-
  unused, documenting the RQ/Redis seam described in
  `docs/ARCHITECTURE_SPEC.md` §3.3.4 without pretending it's wired up.

## [0.5.0] — Phase 4: Auth, RBAC, JSON API, ticket integrations

### Added
- **Auth** (Slice 1, §10.1): real per-user session login (Flask-Login +
  Flask-WTF + argon2 password hashing), replacing the hardcoded seeded
  "Demo Analyst" actor every mutating action had been attributed to since
  Phase 1.
- **RBAC** (Slice 2, §10.2): admin/analyst/read_only capability matrix
  enforced two ways — route-level `@require_role` plus internal role checks
  on the two capabilities with an admin/analyst split (connect-account,
  accept-risk) — driving the drawer, row actions, context menu, and
  keyboard shortcuts identically so there's one source of truth for what a
  role can do.
- **User admin & settings** (Slice 3, §10.3): admin user CRUD with a
  last-active-admin lockout (can't deactivate or demote the last admin), a
  self-service profile/password page, and a deactivation that now takes
  effect on a user's very next request, not just their next login.
- **JSON API** (Slices 4a/4b, §10.4): a `flask-smorest` + `marshmallow`
  `/api/v1` blueprint tree with its own JWT bearer-token auth (independent
  of the HTML app's session cookie), Swagger UI at `/api/docs`, and both a
  read surface (accounts/runs/findings/principals/graph/compliance/checks)
  and a mutating surface (every workflow action the HTML app has) behind
  the same RBAC matrix.
- **Ticket/webhook integrations** (Slice 5, §7.5): a `TicketAdapter`
  protocol with a real `WebhookAdapter` (genuine outbound JSON POST) plus
  permanent, honestly-labeled Jira/Slack stubs (no OAuth is wired up
  anywhere in this app, so they always return a `"... (simulated)"` ref,
  never pretending to be a real created ticket).

## [0.4.0] — Phase 3: Blast-radius graph, least-privilege, compliance dashboard

### Added
- **Permission graph & blast radius** (Slice 1, §6.2): a `networkx`-based
  graph over principals/policies/actions/resources, populating real
  blast-radius scores and escalation paths that `risk.py`'s impact scoring
  had only ever read as a placeholder `0` before this.
- **Blast-radius graph view** (Slice 2): a vendored-Cytoscape UI over the
  permission graph, per-principal and account-wide, highlighting the
  concrete escalation path (e.g. `intern -> iam:CreateAccessKey -> bob`)
  when one exists.
- **Least-privilege recommendation engine** (Slice 3, §6.3): diffs a
  principal's granted vs. actually-used (from CloudTrail) actions and
  suggests a reduced policy, gated on a minimum observation window/event
  count so it never asserts a recommendation off sparse data.
- **Compliance page & checks catalog** (Slice 4, §6.5): a per-framework
  (CIS AWS 1.4 / SOC 2 / NIST 800-53) pass/fail checklist and a full
  registry browser for all 20 checks.
- **Composite risk / posture retune & dashboard** (Slice 5, §6.4): fixed a
  long-standing score-saturation bug (every scanned account scored 0/F
  regardless of actual severity) by reworking the posture formula around a
  diminishing-returns, weighted risk load instead of a raw score sum; added
  the account dashboard (posture gauge, severity tiles, trend, riskiest
  principals).

## [0.3.0] — Phase 2: Simulated cloud ingestion, scheduling, diff

### Added
- **Moto-simulated AWS org** (Slice 1, §5.2): a deterministic, seeded "Acme
  Corp" org (10 users, 6 roles, 5 managed policies with a deliberate
  spread of misconfigurations and deliberately-clean principals) ingested
  through genuine `boto3` IAM calls against a `moto` mock — the marquee
  demo account; file upload remains the alternate ingestion path.
- **Connect wizard & Accounts page** (Slice 2, §5.3): demo / assume-role /
  file-upload connection methods, all validated before either the account
  or the first scan is created.
- **Background execution & live progress** (Slice 3, §3.3.4/§8.10): an
  in-process `ThreadingJobQueue` (see the addendum in
  `docs/ARCHITECTURE_SPEC.md` — this superseded the doc's originally-planned
  RQ/Redis worker topology) plus a Runs page that self-polls via htmx until
  a scan reaches a terminal status.
- **Run-to-run diff & deterministic seed drift** (Slice 4, §5.4/§8.9): a
  compute-on-demand diff between any two runs (severity/risk/status/evidence
  deltas), plus a deterministic "drift stage" the demo org advances through
  on repeated scans so there's always something real to diff.
- **Recurring scans & real exception-expiry job** (Slice 5, §5.5/§11.4): an
  in-process APScheduler (also superseding the doc's RQ/Redis-adjacent
  design) promotes the opportunistic on-read exception-expiry check from
  Phase 1 into a real daily job.

## [0.2.0] — Phase 1: Findings workflow & UX shell

### Added
- **Findings table & app shell** (Slice 1, §8.2): server-side sort/filter/
  paginate, severity facets, dark/light theme — vendored htmx + Alpine.js,
  no CDN dependency.
- **Finding detail drawer, status workflow & audit trail** (Slice 2a, §7.1):
  a state machine driving both the allowed transitions and the drawer's own
  buttons from one source of truth, so they can't drift apart.
- **Comments & assignment** (Slice 2b): a unified activity timeline merging
  status history, comments, and assignment events.
- **Suppression / accepted-risk exceptions** (Slice 2c, §7.4): time-bound
  exceptions with auto-expiry re-surfacing (opportunistic on read; promoted
  to a real scheduled job in Phase 2 Slice 5).
- **Context menu, command palette & keyboard shortcuts** (Slice 3,
  §8.3-8.6): single/bulk right-click actions, a `Cmd/Ctrl+K` palette with
  live server-searched findings, and a full keyboard-navigation layer —
  closing out Phase 1's workflow/UX scope in full.

## [0.1.0] — Phase 0: Foundation & backend spine

### Added
- **Domain layer** (`app/domain`): pure records, enums, forgiving timestamp
  helpers, the finding fingerprint, an AWS policy-document reader, and a robust
  log parser (plaintext key=value + CloudTrail JSON) that never crashes on bad input.
- **Rule registry + engine** (`app/analysis`): 20 self-describing checks across
  identity, credential, policy, privilege/escalation, log, and inventory
  categories; composite risk scoring and account posture score/grade.
- **Compliance mapping** (`app/compliance`): single-table check → CIS AWS 1.4 /
  SOC 2 / NIST 800-53 control mapping.
- **Ingestion** (`app/ingestion`): `IngestionAdapter` interface + `FileIngestionAdapter`
  (CSV inventory + JSON policies + auth log) and a source-agnostic normalizer.
- **Persistence** (`app/models`, `app/db`): full SQLAlchemy 2.0 schema (16 tables)
  with Alembic migrations; SQLite (WAL) by default, Postgres-ready via `DATABASE_URL`.
- **Services** (`app/services`): `ScanService` orchestrates ingest → analyze →
  persist with fingerprint-based cross-run finding-group correlation; JSON/CSV export.
- **CLI** (`app/cli`): `init-db`, `checks`, `scan`, `export`.
- **Quality gate**: ruff (lint+format), mypy (strict on core logic), pytest with
  Hypothesis property tests; 92% coverage. GitHub Actions CI + pre-commit.

[Unreleased]: #
[0.5.0]: #
[0.4.0]: #
[0.3.0]: #
[0.2.0]: #
[0.1.0]: #
