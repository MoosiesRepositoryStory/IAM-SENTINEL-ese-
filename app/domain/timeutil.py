"""Small, dependency-light time helpers.

Everything in the app works in UTC. ``parse_dt`` is intentionally forgiving:
inventory data arrives from CSVs, REST APIs, and CloudTrail with a variety of
timestamp shapes, and a parser that raises on the first odd value is exactly the
brittleness §12 warns about.
"""

from __future__ import annotations

from datetime import UTC, datetime

from dateutil import parser as _dateparser


def utcnow() -> datetime:
    """Timezone-aware current time in UTC."""
    return datetime.now(UTC)


def parse_dt(value: object) -> datetime | None:
    """Best-effort parse of an arbitrary timestamp into a UTC ``datetime``.

    Returns ``None`` for empty / unparseable input rather than raising, and
    always returns a timezone-aware datetime (naive inputs are assumed UTC).
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).strip()
    if not text or text.lower() in {"none", "null", "never", "n/a", "-"}:
        return None
    try:
        dt = _dateparser.parse(text)
    except (ValueError, OverflowError, TypeError):
        return None
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def to_iso(dt: datetime | None) -> str | None:
    """Serialize a datetime to an ISO-8601 UTC string, or ``None``."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat()


def days_since(dt: datetime | None, *, now: datetime | None = None) -> int | None:
    """Whole days between ``dt`` and now (UTC). ``None`` if ``dt`` is None."""
    if dt is None:
        return None
    reference = now or utcnow()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return (reference - dt).days
