"""Application configuration, sourced from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_DATA = _ROOT / "data"


_DEV_SECRET = "dev-insecure-change-me"
_MIN_PRODUCTION_SECRET_LENGTH = 32


@dataclass(frozen=True)
class Settings:
    database_url: str
    data_dir: Path
    reports_dir: Path
    secret_key: str
    jwt_secret_key: str
    sync_jobs: bool
    public_base_url: str | None
    public_mode: bool
    environment: str

    @classmethod
    def from_env(cls) -> Settings:
        data_dir = Path(os.getenv("DATA_DIR", str(_DEFAULT_DATA)))
        default_db = f"sqlite:///{(data_dir / 'sentinel.db').as_posix()}"
        secret_key = os.getenv("SECRET_KEY", _DEV_SECRET)
        return cls(
            database_url=os.getenv("DATABASE_URL", default_db),
            data_dir=data_dir,
            reports_dir=Path(os.getenv("REPORTS_DIR", str(data_dir / "reports"))),
            secret_key=secret_key,
            # Separate signing key for API bearer tokens (app/api/auth.py) so
            # a leak of one key (e.g. via a session-cookie-adjacent bug) can't
            # also forge the other. Falls back to secret_key when unset,
            # matching today's actual runtime behavior (both currently read
            # SECRET_KEY) — an explicit JWT_SECRET_KEY is what makes the two
            # genuinely independent; see Settings.validate() for why
            # production requires them to differ.
            jwt_secret_key=os.getenv("JWT_SECRET_KEY") or secret_key,
            sync_jobs=os.getenv("SYNC_JOBS", "true").lower() in {"1", "true", "yes"},
            # Canonical external base URL (e.g. "https://sentinel.example.com"),
            # e.g. for ticket-notification deep links (views.finding_create_ticket
            # / api.findings) — see app/web/__init__.py's create_app(). Unset by
            # default: dev/demo keeps Flask's normal behavior of deriving
            # external URLs from the incoming request's Host header.
            public_base_url=os.getenv("PUBLIC_BASE_URL") or None,
            # Public-demo hardening (docs/ARCHITECTURE_SPEC.md §13.6): when
            # on, app.services.rbac.at_least() clamps every capability above
            # read_only to always-denied, regardless of the caller's actual
            # role — see that module for why centralizing the clamp there
            # (rather than at each route/service call site) matters. Off by
            # default: a normal deployment's seeded admin/analyst accounts
            # keep their real capabilities.
            public_mode=os.getenv("PUBLIC_MODE", "false").lower() in {"1", "true", "yes"},
            # Gates Settings.validate()'s fail-closed checks below. Anything
            # other than the literal "production" (unset, "development",
            # "testing") keeps today's lenient dev/demo behavior unchanged.
            environment=os.getenv("ENVIRONMENT", "development"),
        )

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def validate(self) -> None:
        """Fail closed at startup rather than silently signing sessions/JWTs
        with a known, public default. Only enforced when ENVIRONMENT is
        explicitly "production" — dev/demo/test keep working with the
        documented insecure defaults unchanged."""
        if self.environment != "production":
            return
        for name, value in (
            ("SECRET_KEY", self.secret_key),
            ("JWT_SECRET_KEY", self.jwt_secret_key),
        ):
            if value == _DEV_SECRET:
                raise RuntimeError(
                    f"ENVIRONMENT=production but {name} is still the dev default — "
                    "set a real, high-entropy value."
                )
            if len(value) < _MIN_PRODUCTION_SECRET_LENGTH:
                raise RuntimeError(
                    f"ENVIRONMENT=production requires {name} to be at least "
                    f"{_MIN_PRODUCTION_SECRET_LENGTH} characters (got {len(value)})."
                )
        if self.secret_key == self.jwt_secret_key:
            raise RuntimeError(
                "ENVIRONMENT=production requires SECRET_KEY and JWT_SECRET_KEY to be "
                "different values — set JWT_SECRET_KEY explicitly (a shared key means "
                "leaking either one forges both the session cookie and API tokens)."
            )


def get_settings() -> Settings:
    return Settings.from_env()
