# E2E suite (Playwright)

Browser-driven regression tests for the flows highest-value enough to justify
a real browser: login/logout + RBAC gating across all three seeded roles, one
full findings-workflow cycle (transition/comment/assign/suppress), the
run-to-run diff view, and blast-radius graph rendering. Not an attempt to
recreate every ad hoc verification script written across every phase (see
CHANGELOG/commit history) — those did their job at the time; this is the
small, maintained subset worth keeping green forever.

Deliberately **not** collected by the regular `pytest -q` run (see
`pyproject.toml`'s `norecursedirs`) — it needs a live server + seeded
database + a browser binary, none of which the unit-test job has.

## Running locally

```bash
pip install -e ".[dev,e2e]"
playwright install chromium

# Terminal 1 — seed a scratch DB, then serve it:
export DATA_DIR=/tmp/sentinel-e2e
python tests/e2e/seed.py
python tests/e2e/server.py 5000

# Terminal 2:
pytest tests/e2e --base-url=http://127.0.0.1:5000
```

`seed.py` and `server.py` must run with the *same* `DATA_DIR` as each other
(two processes sharing one SQLite file in WAL mode — see `app/db.py`); leave
`DATABASE_URL` unset and let `Settings.from_env()` derive it from `DATA_DIR`
alone (`sqlite:///<data_dir>/sentinel.db`) — setting it explicitly yourself
is easy to get subtly wrong (a manually-built `sqlite:///` URL and a
platform's own path separator conventions don't always agree). Re-running
`seed.py` against a non-empty DB just adds another account; delete the
scratch DB file to start clean.

## CI wiring

The `e2e` job in `.github/workflows/ci.yml` runs as a separate job from
`quality` (the pytest/ruff/mypy job) — installs the `e2e` extra + a Chromium
binary, runs `seed.py`, backgrounds `server.py`, polls `/healthz`, runs this
suite, then tears the server down. It does not block on `quality` finishing
(the two run in parallel) but both must pass for CI to go green overall.

## What's intentionally not here

Exhaustive route × role matrices, disabled-target edge cases, every ad hoc
verification click-through ever run by hand — all already covered at the
right layer by the Flask-test-client unit suite (`tests/test_authz.py`,
`tests/test_workflow_service.py`, etc.), which is faster and doesn't need a
browser. This suite only covers what a real browser is uniquely positioned to
catch: a genuine login session, real client-side JS (Alpine reveals, htmx
swaps, Cytoscape rendering), and controls that are supposed to not exist in
the DOM for a given role rather than just being server-side-rejected.
