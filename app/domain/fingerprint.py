"""Finding fingerprint (§4.5) — the anchor for cross-run workflow continuity.

The fingerprint MUST be stable across runs for the same logical issue and MUST
NOT include volatile data (timestamps, run ids, counts, evidence). Evidence and
risk score may change run to run; the fingerprint may not.
"""

from __future__ import annotations

import hashlib


def fingerprint(
    check_id: str,
    principal_uid: str | None = None,
    resource: str | None = None,
    policy_uid: str | None = None,
) -> str:
    """Deterministic sha256 identity for a logical finding.

    >>> fingerprint("iam.user.mfa_disabled", "user/intern") == \
    ...     fingerprint("iam.user.mfa_disabled", "user/intern")
    True
    """
    parts = [check_id, principal_uid or "", resource or "", policy_uid or ""]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
