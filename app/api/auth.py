"""API bearer-token auth (§10.4, Phase 4 Slice 4a): JWT issued by
``POST /api/v1/auth/login``, verified via ``Authorization: Bearer <token>`` on
every other route. Deliberately independent of the HTML app's Flask-Login
session (see ``app.web.auth_views``'s docstring) — a caller authenticates to
the API by presenting a token, never a session cookie, and vice versa.

Role enforcement reuses the exact same capability matrix as the HTML app
(``app.services.rbac``) — see :func:`require_api_role`. Every route in this
slice only needs ``Capability.VIEW`` (any authenticated role), since Slice 4a
is read-only; :func:`require_api_role` exists now so 4b's mutating routes
reuse it unchanged rather than inventing a second gating mechanism.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any, TypeVar

import jwt
from flask import current_app, g, request
from flask_smorest import Blueprint

from app.api.errors import ApiError
from app.api.schemas import LoginRequestSchema, TokenResponseSchema
from app.db import session_scope
from app.domain.timeutil import to_iso
from app.models import AppUser
from app.services.auth_service import AuthError, authenticate
from app.services.rbac import at_least

ALGORITHM = "HS256"
TOKEN_TTL = timedelta(hours=12)

blp = Blueprint("auth", __name__, url_prefix="/api/v1/auth", description="Token issuance")

F = TypeVar("F", bound=Callable[..., Any])


def create_token(user: AppUser, secret_key: str) -> tuple[str, datetime]:
    """Sign a token carrying ``user_id``/``role``/``exp`` with a ~12h expiry
    (the Phase 4-locked decision: logout = client-discard token, no
    server-side revocation list). The ``role`` claim is informational only
    (a client can introspect it without a round trip) — every request still
    re-derives authorization from a FRESH DB load keyed on ``user_id`` (see
    :func:`_authenticate_request`), never from this claim, so a role change
    or deactivation takes effect on the very next request rather than
    waiting out the token's remaining ~12h."""
    now = datetime.now(UTC)
    expires_at = now + TOKEN_TTL
    payload = {
        "user_id": user.id,
        "role": user.role,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    token = jwt.encode(payload, secret_key, algorithm=ALGORITHM)
    return token, expires_at


def _decode_token(token: str, secret_key: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, secret_key, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise ApiError(401, "token_expired", "Token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        raise ApiError(401, "invalid_token", "Invalid or malformed token.") from exc


def _authenticate_request() -> AppUser:
    """Verify the bearer token and load a FRESH ``AppUser`` row (not just
    trusting the token's ``role`` claim) — deliberately re-checks
    ``is_active`` against the DB on every request, mirroring the HTML app's
    own Slice 3 fix (Flask-Login's ``user_loader`` returning ``None`` for a
    deactivated user) so a deactivated account's token stops working
    immediately rather than staying valid until it naturally expires up to
    12h later."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise ApiError(401, "unauthorized", "Missing or malformed Authorization header.")
    token = header[len("Bearer ") :].strip()
    if not token:
        raise ApiError(401, "unauthorized", "Missing or malformed Authorization header.")

    payload = _decode_token(token, current_app.config["SECRET_KEY"])
    with session_scope() as session:
        user = session.get(AppUser, payload.get("user_id"))
        if user is None or not user.is_active:
            raise ApiError(401, "unauthorized", "Account is deactivated or no longer exists.")
        session.expunge(user)
    return user


def api_login_required(fn: F) -> F:
    """Require a valid bearer token; makes the caller available via
    :func:`current_api_user` for the rest of the request."""

    @wraps(fn)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        g.api_user = _authenticate_request()
        return fn(*args, **kwargs)

    return wrapped  # type: ignore[return-value]


def require_api_role(minimum: str) -> Callable[[F], F]:
    """Require a valid bearer token AND that its user's role meets
    ``minimum`` on the read_only < analyst < admin ladder (§10.2's
    ``app.services.rbac``) — the API's equivalent of
    ``app.web.authz.require_role``, same capability matrix, same 403
    envelope on denial."""

    def decorator(fn: F) -> F:
        @wraps(fn)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            user = _authenticate_request()
            if not at_least(user.role, minimum):
                raise ApiError(
                    403, "forbidden", f"This action requires the '{minimum}' role or higher."
                )
            g.api_user = user
            return fn(*args, **kwargs)

        return wrapped  # type: ignore[return-value]

    return decorator


def current_api_user() -> AppUser:
    """The authenticated caller for this request — only valid inside a view
    wrapped by :func:`api_login_required` or :func:`require_api_role`."""
    return g.api_user


@blp.route("/login", methods=["POST"])
@blp.arguments(LoginRequestSchema, location="json")
@blp.response(200, TokenResponseSchema)
@blp.doc(security=[])  # the one endpoint reachable without a token
def login(payload: dict[str, Any]) -> dict[str, Any]:
    """Exchange email + password for a bearer token (~12h expiry)."""
    with session_scope() as session:
        try:
            user = authenticate(session, payload["email"], payload["password"])
        except AuthError as exc:
            raise ApiError(401, "invalid_credentials", str(exc)) from exc
        session.expunge(user)

    token, expires_at = create_token(user, current_app.config["SECRET_KEY"])
    return {
        "token": token,
        "token_type": "Bearer",
        "expires_at": to_iso(expires_at),
        "user": {
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "role": user.role,
        },
    }
