"""Role-based access control — pure role logic (§10.2, Phase 4 Slice 2).

Three global roles — read_only < analyst < admin, not per-account. This
module is deliberately dependency-free (stdlib only): it's imported by plain
service modules (``exception_service``, ``connect_service``) for their
defense-in-depth re-checks, and those modules must stay importable without
the ``api`` extra (Flask-Login etc.) installed — the base `iam-sentinel`
install only pulls in Flask itself, not Flask-Login. The Flask-specific route
decorator that also belongs to "RBAC" lives in ``app.web.authz`` instead,
which *does* depend on Flask/Flask-Login and is only ever imported from
``app/web/*``.

Enforcement happens in two independent layers per the spec's "defense in
depth" mandate:

1. **Route layer** (``app.web.authz.require_role``): every mutating route is
   decorated with the minimum role it needs. This is the primary gate — it
   runs before any service code, denies with 403, and writes an
   ``access_denied`` ``audit_event``.
2. **Service layer** (this module's :func:`at_least`, used directly inside
   ``exception_service.create_exception`` and ``connect_service.connect_account``):
   the two capabilities where a role split exists *within* an otherwise-shared
   code path — accepting risk (admin) vs. every other exception/workflow
   action (analyst), and connecting an account (admin) — independently
   re-verify the role inside the service function itself. That's what
   "defense in depth" buys: even if some future caller (a bug, a new API
   endpoint in Slice 4) reaches these functions without going through the
   decorated route, an unauthorized accept-risk or account-connect still
   can't happen.

Both layers read from the same :class:`Capability` table, so they can't drift
apart.

**Convention used throughout this slice:** role-aware service functions take
an optional ``actor_role: str | None`` parameter defaulting to ``None`` —
meaning "trusted internal caller, no check performed." This mirrors the
posture ``actor_id: int | None = None`` already has elsewhere in this
codebase for system-triggered calls (e.g. ``expire_exceptions``'s daily
auto-reopen has no human actor at all). Every *real* entry point (a route)
always passes the actual ``current_user.role``; only test/internal callers
that aren't exercising authorization omit it — which also means adding this
parameter didn't require touching the dozens of pre-existing unit tests that
call these functions directly to test unrelated business logic.
"""

from __future__ import annotations

ROLES: tuple[str, ...] = ("read_only", "analyst", "admin")
_RANK: dict[str, int] = {role: i + 1 for i, role in enumerate(ROLES)}


def at_least(role: str | None, minimum: str) -> bool:
    """Whether ``role`` meets or exceeds ``minimum`` on the read_only < analyst
    < admin ladder. An unknown/missing role never satisfies anything."""
    return _RANK.get(role or "", 0) >= _RANK[minimum]


class Capability:
    """Named capabilities from the approved matrix (§10.2), each resolving to
    the minimum role required. Named constants — not a bare ``"admin"``/
    ``"analyst"`` string at each call site — so a route or service's *intent*
    is legible and the whole matrix can be audited from this one place."""

    VIEW = "read_only"
    RUN_SCAN = "analyst"
    MANAGE_SCHEDULE = "analyst"
    CONNECT_ACCOUNT = "admin"
    DELETE_ACCOUNT = "admin"  # no delete-account route exists yet — reserved
    WORKFLOW_TRANSITION = "analyst"  # incl. exception-revoke reopens (de-escalation)
    ASSIGN = "analyst"
    COMMENT = "analyst"
    SUPPRESS = "analyst"
    ACCEPT_RISK_CREATE = "admin"
    CREATE_TICKET = "analyst"  # gates POST /findings/<id>/ticket (Slice 5)
    MANAGE_USERS = "admin"  # gates GET+POST /settings/users/* (Slice 3)
    MANAGE_INTEGRATIONS = "admin"  # gates /settings/integrations/* (Slice 5)
    # Reserved: the /settings shell itself is VIEW-level (any authenticated
    # user — it's a nav hub, not a mutation), so nothing currently gates on
    # MANAGE_SETTINGS directly. Individual settings sub-pages get their own
    # specific capability as they're built (MANAGE_USERS, MANAGE_INTEGRATIONS).
    MANAGE_SETTINGS = "admin"


class PermissionDenied(PermissionError):
    """Raised by a service-layer re-check (see module docstring) — distinct
    from each service's own ``ValueError``-based input-validation errors, so
    callers can tell "you're not allowed to do this" apart from "that input
    was invalid"."""
