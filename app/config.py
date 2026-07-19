"""Application configuration, sourced from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_DATA = _ROOT / "data"


@dataclass(frozen=True)
class Settings:
    database_url: str
    data_dir: Path
    reports_dir: Path
    secret_key: str
    sync_jobs: bool
    public_base_url: str | None

    @classmethod
    def from_env(cls) -> Settings:
        data_dir = Path(os.getenv("DATA_DIR", str(_DEFAULT_DATA)))
        default_db = f"sqlite:///{(data_dir / 'sentinel.db').as_posix()}"
        return cls(
            database_url=os.getenv("DATABASE_URL", default_db),
            data_dir=data_dir,
            reports_dir=Path(os.getenv("REPORTS_DIR", str(data_dir / "reports"))),
            secret_key=os.getenv("SECRET_KEY", "dev-insecure-change-me"),
            sync_jobs=os.getenv("SYNC_JOBS", "true").lower() in {"1", "true", "yes"},
            # Canonical external base URL (e.g. "https://sentinel.example.com"),
            # e.g. for ticket-notification deep links (views.finding_create_ticket
            # / api.findings) — see app/web/__init__.py's create_app(). Unset by
            # default: dev/demo keeps Flask's normal behavior of deriving
            # external URLs from the incoming request's Host header.
            public_base_url=os.getenv("PUBLIC_BASE_URL") or None,
        )

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    return Settings.from_env()
