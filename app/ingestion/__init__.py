"""Ingestion adapters + normalization.

Every source (file / REST / moto-AWS) implements :class:`IngestionAdapter` and
returns a :class:`RawDataset`; :func:`normalize` turns that into the canonical
:class:`~app.domain.records.NormalizedDataset` the engine consumes.
"""

from importlib.util import find_spec as _find_spec

# Registering the built-in adapters as a side effect.
from app.ingestion import file_adapter as _file_adapter  # noqa: F401
from app.ingestion.base import (
    IngestionAdapter,
    ProgressReporter,
    RawDataset,
    get_adapter,
    register_adapter,
)
from app.ingestion.normalize import normalize

# The moto-AWS adapter needs the optional ``cloud`` extra (boto3 + moto). Register
# it only when those are installed so the app still runs (file adapter only)
# without the extra. ``find_spec`` gates on availability without paying the cost
# of importing boto3 on every startup — the adapter imports it lazily in fetch().
if _find_spec("boto3") is not None and _find_spec("moto") is not None:
    from app.ingestion.moto.adapter import MotoAwsIngestionAdapter

    register_adapter(MotoAwsIngestionAdapter())

__all__ = [
    "IngestionAdapter",
    "ProgressReporter",
    "RawDataset",
    "get_adapter",
    "normalize",
    "register_adapter",
]
