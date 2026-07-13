"""Rule registry + analysis engine.

Importing this package registers every shipped check as a side effect (see
:mod:`app.analysis.checks`), so ``from app import analysis`` is enough to make
``analysis.REGISTRY`` fully populated.
"""

# Populate the registry by importing the check modules.
from app.analysis import checks as _checks  # noqa: E402,F401
from app.analysis.registry import REGISTRY, Check, CheckContext, CheckMeta, register

__all__ = ["REGISTRY", "Check", "CheckContext", "CheckMeta", "register"]
