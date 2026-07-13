"""Enumerations shared across the domain.

These are ``str``-backed enums so they serialize cleanly to JSON / the DB and
compare naturally against raw strings coming from the API or CSV.
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Higher = more severe. Useful for sorting."""
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[self.value]

    @property
    def base_weight(self) -> int:
        """Base severity weight used by the risk scorer (§6.4)."""
        return {"LOW": 20, "MEDIUM": 45, "HIGH": 70, "CRITICAL": 90}[self.value]


class Category(StrEnum):
    IDENTITY = "identity"
    PRIVILEGE = "privilege"
    CREDENTIAL = "credential"
    HYGIENE = "hygiene"
    POLICY = "policy"
    LOG = "log"
    INVENTORY = "inventory"


class Status(StrEnum):
    """Durable workflow status of a finding group (§7.1)."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    ACCEPTED_RISK = "accepted_risk"


class ExceptionKind(StrEnum):
    SUPPRESSED = "suppressed"
    ACCEPTED_RISK = "accepted_risk"


class RunStatus(StrEnum):
    QUEUED = "queued"
    INGESTING = "ingesting"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"

    @property
    def is_terminal(self) -> bool:
        return self in {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELED}
