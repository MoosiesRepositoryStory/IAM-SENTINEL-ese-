"""Importing this package registers every shipped check.

Order does not matter; each module registers its checks at import time.
"""

from app.analysis.checks import (  # noqa: F401
    credential,
    identity,
    inventory,
    log_checks,
    policy_checks,
    privilege,
)

__all__ = ["credential", "identity", "inventory", "log_checks", "policy_checks", "privilege"]
