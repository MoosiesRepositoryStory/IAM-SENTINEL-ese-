"""``GET /api/v1/me`` (§10.4, Phase 4 Slice 4a) — the authenticated caller's
own profile. No service reuse needed beyond the AppUser row itself
(``current_api_user()`` already loaded it fresh for the auth check)."""

from __future__ import annotations

from flask_smorest import Blueprint

from app.api.auth import current_api_user, require_api_role
from app.api.schemas import MeSchema
from app.services.rbac import Capability

blp = Blueprint("me", __name__, url_prefix="/api/v1", description="Caller's own profile")


@blp.route("/me")
@require_api_role(Capability.VIEW)
@blp.response(200, MeSchema)
def get_me() -> object:
    return current_api_user()
