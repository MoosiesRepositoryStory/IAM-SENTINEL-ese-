"""Least-privilege recommendation engine (§6.3, Phase 3 Slice 3).

Emulates IAM Access Analyzer's "policy generation from CloudTrail": diff each
principal's *granted* actions (from its attached policies / the permission
graph) against the actions it *actually used* (from ``log_event`` activity,
normalized to IAM ``service:Action`` form) to find unused grants, and generate
a suggested least-privilege policy covering only what was used.

Pure analysis helper, domain-only dependencies — same layer/posture as
``risk.py`` and ``graph.py``. The ``UnusedGrantsCheck`` calls it; it never
imports the check/registry layer back.

## Sufficiency threshold — the "don't recommend off sparse data" gate

A recommendation is only as trustworthy as the activity behind it, so we gate
confidence on two independent axes and refuse to present a scoped policy unless
BOTH pass:

- **Window length** — the observed log span must be >= ``MIN_WINDOW_DAYS`` (14).
  Below a fortnight you can't tell "never uses this" from "hasn't this week."
  Real IAM Access Analyzer looks back up to 90 days and AWS recommends
  reviewing >= 90; 14 is a deliberately conservative *floor* for the demo, not
  a target.
- **Per-principal observations** — even within a long window, a principal we
  barely saw gives no signal. We require >= ``MIN_PRINCIPAL_EVENTS`` (3)
  observed events (successful, failed, or denied — all evidence the identity
  was actually captured) before concluding a grant is unused. With fewer, "we
  saw them use nothing" is indistinguishable from "we barely saw them," so the
  recommendation is flagged insufficient rather than asserted.

When either gate fails, no suggested policy is produced; the recommendation
carries an explicit "insufficient activity history" reason naming the observed
window and event count, so an operator knows to broaden log coverage before
acting rather than trusting a hollow recommendation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from app.domain import policy as pol
from app.domain.records import PolicyRecord

MIN_WINDOW_DAYS = 14
MIN_PRINCIPAL_EVENTS = 3
# Share of granted sensitive actions that must be unused before it's worth a
# finding (§6.3 step 3's ">60%").
UNUSED_RATIO_THRESHOLD = 0.6


@dataclass
class LeastPrivilegeRecommendation:
    principal_uid: str
    granted_sensitive: list[str]
    unused_sensitive: list[str]
    used_actions: list[str]
    window_days: int
    event_count: int
    confident: bool
    insufficient_reason: str | None
    suggested_policy: dict | None
    summary: str

    @property
    def suggested_policy_json(self) -> str | None:
        if self.suggested_policy is None:
            return None
        return json.dumps(self.suggested_policy, indent=2)

    @property
    def unused_ratio(self) -> float:
        if not self.granted_sensitive:
            return 0.0
        return len(self.unused_sensitive) / len(self.granted_sensitive)

    @property
    def exceeds_threshold(self) -> bool:
        return bool(self.unused_sensitive) and self.unused_ratio >= UNUSED_RATIO_THRESHOLD


def _sensitive(actions: set[str]) -> set[str]:
    return {a for a in actions if pol.is_sensitive_action(a, pol.SENSITIVE_ACTIONS)}


def _is_exercised(granted_action: str, used: set[str]) -> bool:
    """Whether a granted action (possibly a wildcard like ``s3:*``) was
    exercised by any concrete used action falling under it."""
    return any(pol.grants_action({granted_action}, u) for u in used)


def _action_resources(policies: list[PolicyRecord]) -> dict[str, set[str]]:
    """Map each action a principal's Allow statements grant -> the resources
    they grant it on, so a suggested policy can keep the original resource
    scope rather than widening it to ``*``."""
    out: dict[str, set[str]] = {}
    for p in policies:
        for st in pol.statements(p.document):
            if not pol.is_allow(st):
                continue
            acts = pol.actions(st) or (["*"] if pol.not_actions(st) else [])
            res = set(pol.resources(st)) or {"*"}
            for a in acts:
                out.setdefault(a, set()).update(res)
    return out


def _has_unsupported_forms(policies: list[PolicyRecord]) -> bool:
    """Whether any of a principal's attached policies uses a statement form
    this tool's Allow-only structural model can't safely reduce: an explicit
    ``Deny`` (never evaluated anywhere in this engine — see
    ``domain.policy``'s module docstring — so a Deny-restricted action can
    read as "granted" here), a ``Condition`` key (entirely unmodeled; a
    conditionally-scoped grant would become unconditional in a generated
    policy), or ``NotAction``/``NotResource`` (their exclusion semantics are
    already lost by the time actions/resources reach this module).

    A blanket per-principal check, not a per-statement one: refusing more
    broadly than strictly necessary is the safe failure mode for a tool whose
    output is meant to be a real access-narrowing action.
    """
    for p in policies:
        for st in pol.statements(p.document):
            if not pol.is_allow(st):
                return True
            if "Condition" in st:
                return True
            if pol.not_actions(st):
                return True
            if "NotResource" in st:
                return True
    return False


def _resources_for(action: str, action_resources: dict[str, set[str]]) -> list[str]:
    """Resources to scope ``action`` to in the suggested policy: an exact
    statement's resources if present, else the union from any wildcard
    statement that covers it, else ``*``."""
    if action in action_resources:
        return sorted(action_resources[action])
    covering: set[str] = set()
    for granted, res in action_resources.items():
        if pol.grants_action({granted}, action):
            covering |= res
    return sorted(covering) if covering else ["*"]


def _build_policy(used: set[str], policies: list[PolicyRecord]) -> dict:
    """A minimal policy document granting exactly ``used``, grouped into one
    statement per distinct resource set (deterministic ordering)."""
    action_resources = _action_resources(policies)
    by_res: dict[tuple[str, ...], list[str]] = {}
    for action in sorted(used):
        res = tuple(_resources_for(action, action_resources))
        by_res.setdefault(res, []).append(action)
    statements = [
        {
            "Effect": "Allow",
            "Action": actions,
            "Resource": list(res) if len(res) > 1 else res[0],
        }
        for res, actions in sorted(by_res.items())
    ]
    return {"Version": "2012-10-17", "Statement": statements}


def recommend(
    *,
    principal_uid: str,
    granted_actions: set[str],
    policies: list[PolicyRecord],
    used_actions: set[str],
    event_count: int,
    window_days: int,
) -> LeastPrivilegeRecommendation:
    """Compute the granted-vs-used diff and a suggested least-privilege policy
    (or an insufficient-data advisory) for one principal."""
    granted_sensitive = _sensitive(granted_actions) - {"*"}
    unused_sensitive = sorted(g for g in granted_sensitive if not _is_exercised(g, used_actions))
    # Only actions that are both used AND actually covered by current grants
    # belong in a least-privilege *subset* of what the principal already has.
    kept = {u for u in used_actions if pol.grants_action(granted_actions, u)}

    reason: str | None = None
    unsupported_forms = False
    if window_days < MIN_WINDOW_DAYS:
        reason = (
            f"insufficient activity history: only {window_days} day(s) of logs "
            f"observed (need >= {MIN_WINDOW_DAYS})"
        )
    elif event_count < MIN_PRINCIPAL_EVENTS:
        reason = (
            f"insufficient activity for this principal: only {event_count} event(s) "
            f"observed (need >= {MIN_PRINCIPAL_EVENTS})"
        )
    elif _has_unsupported_forms(policies):
        unsupported_forms = True
        reason = (
            "the source policy uses Deny, Condition, NotAction, or NotResource, "
            "which this tool's structural model does not evaluate"
        )
    if reason is not None:
        tail = (
            "Review the policy manually — a generated policy could silently "
            "broaden effective access by dropping the unsupported form."
            if unsupported_forms
            else "Broaden log coverage before removing grants."
        )
        summary = f"Cannot generate a confident least-privilege policy — {reason}. {tail}"
        suggested: dict | None = None
    elif not kept:
        summary = (
            f"This principal used none of its {len(granted_sensitive)} sensitive granted "
            f"action(s) in the observed {window_days}-day window "
            f"({event_count} events seen). Suggested policy grants nothing — consider "
            "detaching all policies."
        )
        suggested = _build_policy(kept, policies)
    else:
        summary = (
            f"Based on {window_days} days of activity ({event_count} events), this "
            f"principal used {len(kept)} of its granted action(s). Suggested "
            "least-privilege policy grants only those."
        )
        suggested = _build_policy(kept, policies)

    return LeastPrivilegeRecommendation(
        principal_uid=principal_uid,
        granted_sensitive=sorted(granted_sensitive),
        unused_sensitive=unused_sensitive,
        used_actions=sorted(kept),
        window_days=window_days,
        event_count=event_count,
        confident=reason is None,
        insufficient_reason=reason,
        suggested_policy=suggested,
        summary=summary,
    )
