"""The route-layer half of RBAC (§10.2, Phase 4 Slice 2) — see
``app.services.rbac``'s module docstring for the full two-layer design. This
half is Flask-specific (route decorator + request context), so it lives under
``app/web`` rather than in the framework-agnostic services layer.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

from flask import abort, request
from flask_login import current_user

from app.db import session_scope
from app.models import AuditEvent
from app.services.rbac import at_least

F = TypeVar("F", bound=Callable[..., Any])


def require_role(minimum: str) -> Callable[[F], F]:
    """Route decorator: 403 (+ an ``access_denied`` audit_event) if
    ``current_user``'s role doesn't meet ``minimum``. Must run on a route
    already behind the blueprint's login gate (``bp.before_request`` in
    views.py) — ``current_user`` is always authenticated by the time this
    executes, so this only ever distinguishes *which* authenticated role is
    asking, not whether anyone is logged in at all."""

    def decorator(view: F) -> F:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if not at_least(current_user.role, minimum):
                _record_denial(minimum)
                abort(403)
            return view(*args, **kwargs)

        return wrapped  # type: ignore[return-value]

    return decorator


def _record_denial(minimum: str) -> None:
    with session_scope() as session:
        session.add(
            AuditEvent(
                actor_id=current_user.id,
                action="access_denied",
                target=request.path,
                event_metadata={
                    "required_role": minimum,
                    "actual_role": current_user.role,
                    "method": request.method,
                },
            )
        )
