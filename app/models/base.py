"""SQLAlchemy declarative base + shared column helpers."""

from __future__ import annotations

from typing import Any

from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.domain.timeutil import to_iso, utcnow


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""

    type_annotation_map = {dict[str, Any]: __import__("sqlalchemy").JSON}


def now_iso() -> str:
    """Current UTC timestamp as an ISO-8601 string (the app's stored form)."""
    iso = to_iso(utcnow())
    assert iso is not None
    return iso


class TimestampMixin:
    created_at: Mapped[str] = mapped_column(String, default=now_iso, nullable=False)
