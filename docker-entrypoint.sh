#!/bin/sh
# Runs pending Alembic migrations (idempotent — a no-op once the DB is
# current), then execs whatever command the image/compose was given
# (normally gunicorn, see the Dockerfile's CMD) so it becomes PID 1 and
# receives signals directly rather than running as a child of this script.
set -e

alembic upgrade head

exec "$@"
