"""Runs the real Flask app for the Playwright E2E suite (see README.md).

Not the CLI's own dev-server story (there isn't one — ``iam-sentinel`` is a
one-shot scan tool, no `runserver` command; see ``app/cli.py``) and
deliberately not ``flask run`` either, to avoid that CLI's own app-factory
autodetection — this just calls ``create_app()`` directly, the same thing
every ad hoc verification script across every phase has done (see e.g. Phase
3 Slice 2's "dev-server verification recipe" note).

    python tests/e2e/server.py [port]

Backgrounded by the CI e2e job (and can be backgrounded locally the same
way); ``GET /healthz`` is what the caller polls to know it's ready.
"""

from __future__ import annotations

import sys

from app.db import create_all
from app.web import create_app


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    create_all()  # no-op if seed.py already ran against the same DB
    app = create_app()
    app.run(host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
