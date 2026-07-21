# Contributing to IAM Sentinel

Thanks for your interest. This is a portfolio project, but it's built to real
standards — the same green gate that guards `master` guards every change.

## Development environment

Python 3.11+ is required.

```bash
python -m venv .venv
. .venv/Scripts/activate          # bash/macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"           # core app + test/lint/type tooling
iam-sentinel init-db              # create the local SQLite schema
```

`pip install -e ".[dev]"` pulls in the `cloud` (boto3/moto) and `graph`
(networkx) dependencies too, so the simulated-AWS and blast-radius test
suites actually run rather than skipping.

Optional extras, installed on top of `dev` only when you need them:

- `.[e2e]` + `playwright install chromium` — the browser-driven end-to-end
  suite. See [`tests/e2e/README.md`](tests/e2e/README.md) for how to seed a
  scratch DB, run the server, and point the suite at it.
- `.[docker]` — `gunicorn` + `psycopg[binary]`, only needed if you're running
  the container or the Postgres-backed `docker compose` stack locally.

To run the app:

```bash
iam-sentinel init-db
python -c "from app.web import create_app; create_app().run(debug=True)"
# then open http://127.0.0.1:5000 and sign in with a seeded demo account
# (admin/analyst/read_only — printed by seed_demo_users() on first boot).
```

Or the whole stack against real Postgres in one command:

```bash
docker compose up --build
```

## Running the checks

These are exactly what CI runs — get them green locally before pushing:

```bash
ruff check .              # lint
ruff format --check .     # formatting (run `ruff format .` to auto-fix)
mypy app/                 # types
pytest -q --cov=app --cov-fail-under=88   # unit + integration tests
```

The end-to-end (`tests/e2e/`) and Docker suites are **not** collected by a
plain `pytest -q` (they need a live server, a browser, or Docker). Run them
the way their docs and the CI jobs do — see `tests/e2e/README.md` and the
`e2e` / `docker` jobs in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Branch & pull-request conventions

- Branch off `master`; keep one logical change per branch.
- Open a pull request against `master`. CI runs three jobs on every PR —
  `quality` (lint/format/type/tests/migration check), `e2e` (Playwright
  against the app run directly), and `docker` (the same E2E suite against the
  containerized app). **All three must be green before merge.**
- PRs are **squash-merged**, so the PR title becomes the commit subject —
  write it as a real, imperative commit summary.
- Keep commits focused and their messages explanatory: say *what changed and
  why*, not just *what*. The existing history (`git log`) and
  [CHANGELOG.md](CHANGELOG.md) are the style reference — match that level of
  detail for anything non-trivial, and add a CHANGELOG entry under
  `[Unreleased]` for user-visible changes.
- Docs-only changes (README, this file, `SECURITY.md`) may be pushed directly
  to `master`; anything touching `app/`, `tests/`, migrations, or CI goes
  through a PR.

## Reporting bugs & proposing changes

Open a [GitHub issue](https://github.com/MoosiesRepositoryStory/IAM-SENTINEL-ese-/issues)
with enough detail to reproduce (what you did, what you expected, what
happened). For anything security-related, follow [SECURITY.md](SECURITY.md)
instead of filing a public issue.
