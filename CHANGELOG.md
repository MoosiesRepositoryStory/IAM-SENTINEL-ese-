# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions track the build phases.

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

[0.1.0]: #
