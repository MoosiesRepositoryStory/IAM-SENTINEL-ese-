"""Checks catalog (§8.11 ``/checks``, Phase 3 Slice 4).

Purely a view over the always-available rule registry (§6.1) plus the
compliance mapping table — no scan required, so the catalog renders even on a
freshly installed, never-scanned instance. When a run is available, each row
also gets its current active-finding count for that run.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis.registry import all_checks
from app.compliance.mappings import compliance_tags_for
from app.models import Finding


@dataclass
class CheckCatalogRow:
    check_id: str
    title: str
    category: str
    severity: str
    description: str
    remediation: str
    compliance_tags: list[str]
    finding_count: int = 0


def _active_finding_counts(session: Session, run_id: int) -> dict[str, int]:
    rows = session.execute(
        select(Finding.check_id, func.count())
        .where(Finding.run_id == run_id, Finding.status.in_(("open", "investigating")))
        .group_by(Finding.check_id)
    ).all()
    counts: dict[str, int] = {}
    for check_id, count in rows:
        counts[check_id] = count
    return counts


def list_checks(session: Session | None = None, run_id: int | None = None) -> list[CheckCatalogRow]:
    """Every registered check, alphabetical by id. ``finding_count`` is 0 for
    every row when no ``(session, run_id)`` is given (e.g. pre-scan)."""
    counts = (
        _active_finding_counts(session, run_id)
        if session is not None and run_id is not None
        else {}
    )
    rows = [
        CheckCatalogRow(
            check_id=check.meta.id,
            title=check.meta.title,
            category=check.meta.category.value,
            severity=check.meta.default_severity.value,
            description=check.meta.description,
            remediation=check.meta.remediation,
            compliance_tags=compliance_tags_for(check.meta.id),
            finding_count=counts.get(check.meta.id, 0),
        )
        for check in all_checks()
    ]
    rows.sort(key=lambda r: r.check_id)
    return rows
