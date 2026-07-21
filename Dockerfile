# syntax=docker/dockerfile:1

# ---- builder ---------------------------------------------------------------
# Installs into a venv in its own stage so the final image never carries pip's
# cache, apt package lists, or a C compiler — none of which the running app
# needs, all of which meaningfully shrink the shipped image.
FROM python:3.11-slim AS builder

WORKDIR /build

# argon2-cffi and psycopg[binary] both ship prebuilt wheels for the common
# platforms this normally builds on, but build-essential is kept here as a
# safety net for whichever platform actually runs this build — it never
# reaches the final image either way.
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY app ./app

RUN python -m venv /venv
ENV PATH="/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir ".[docker]"

# ---- runtime -----------------------------------------------------------
FROM python:3.11-slim AS runtime

RUN useradd --create-home --shell /usr/sbin/nologin sentinel

WORKDIR /app

COPY --from=builder /venv /venv
ENV PATH="/venv/bin:$PATH"

# Run the app from the copied source tree, not the wheel installed into the
# venv: the wheel carries only .py files (no package-data config / MANIFEST.in
# in pyproject.toml), so its `app/web/templates` and `static/` are missing.
# PYTHONPATH=/app makes this complete tree win import resolution unambiguously
# over the (data-file-less) site-packages copy. The venv is still only there
# for the third-party dependencies.
ENV PYTHONPATH=/app
COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Where the SQLite DB (if used) and JSON/CSV report artifacts live — a real
# directory the app user can write to, separate from the read-only /app tree.
ENV DATA_DIR=/data
RUN mkdir -p /data/reports && chown -R sentinel:sentinel /data /app

USER sentinel

EXPOSE 8000

# /healthz is deliberately unauthenticated (see app/web/views.py's
# _PUBLIC_ENDPOINTS) specifically so checks like this one don't need creds.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/healthz', timeout=3)" || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
# One worker, several threads — deliberately NOT multiple worker processes:
# app/scheduler.py runs an in-process APScheduler documented as assuming a
# single process (docs/ARCHITECTURE_SPEC.md's addendum), so N workers would
# start N schedulers and N-fire every scheduled scan. Threads give the
# concurrency a browser needs (parallel HTML/CSS/JS/htmx requests) while
# keeping exactly one scheduler. Each request still gets its own SQLAlchemy
# session via session_scope(), so threaded access is safe.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "app.web:create_app()"]
