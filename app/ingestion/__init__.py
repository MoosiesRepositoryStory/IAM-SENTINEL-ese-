"""Ingestion adapters + normalization.

Every source (file / REST / moto-AWS) implements :class:`IngestionAdapter` and
returns a :class:`RawDataset`; :func:`normalize` turns that into the canonical
:class:`~app.domain.records.NormalizedDataset` the engine consumes.
"""

# Registering the built-in adapters as a side effect.
from app.ingestion import file_adapter as _file_adapter  # noqa: E402,F401
from app.ingestion.base import (
    IngestionAdapter,
    ProgressReporter,
    RawDataset,
    get_adapter,
    register_adapter,
)
from app.ingestion.normalize import normalize

__all__ = [
    "IngestionAdapter",
    "ProgressReporter",
    "RawDataset",
    "get_adapter",
    "normalize",
    "register_adapter",
]
