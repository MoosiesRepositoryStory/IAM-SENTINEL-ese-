"""Pure domain layer: enums, records, dataset, fingerprint, and time helpers.

Nothing in ``app.domain`` may import Flask, SQLAlchemy, boto3, or any I/O
library. It is deliberately kept pure so it is trivially unit-testable and so
the analysis engine can run against data from *any* ingestion source.
"""

from app.domain.enums import Category, ExceptionKind, RunStatus, Severity, Status
from app.domain.fingerprint import fingerprint
from app.domain.records import (
    Finding,
    LogEventRecord,
    NormalizedDataset,
    PolicyRecord,
    PrincipalRecord,
    Thresholds,
)

__all__ = [
    "Category",
    "ExceptionKind",
    "Finding",
    "LogEventRecord",
    "NormalizedDataset",
    "PolicyRecord",
    "PrincipalRecord",
    "RunStatus",
    "Severity",
    "Status",
    "Thresholds",
    "fingerprint",
]
