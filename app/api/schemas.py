"""Marshmallow schemas for the /api/v1 read surface (§10.4, Phase 4 Slice 4a).

Hand-written (not SQLAlchemy-auto-generated) — matching this codebase's
existing style of plain dataclasses over the read services rather than
ORM-derived shapes (see finding_query.py/run_query.py/etc.). Schemas mostly
mirror the read services' own dataclasses/ORM objects field-for-field via
marshmallow's default attribute-name matching, including through
``fields.Nested`` for the composed rows (``AccountRow``, ``RunRow``, ...) —
no manual dict-building needed in the routes.

Timestamps are dumped as-is: every stored timestamp is already an ISO-8601
UTC string at the source (``app.models.base.now_iso``), so there is nothing
to convert.
"""

from __future__ import annotations

from marshmallow import Schema, fields

# ---- errors ----------------------------------------------------------------


class ErrorDetailSchema(Schema):
    code = fields.String()
    message = fields.String()
    details = fields.Raw(allow_none=True)


class ErrorEnvelopeSchema(Schema):
    """Documents the REAL error shape (``app.api.errors``'s
    ``{"error": {"code", "message", "details"}}`` envelope) in the generated
    OpenAPI spec — without this, flask-smorest's own default error schema
    (``{"code", "status", "message", "errors"}``) would show up in Swagger
    instead, describing a response shape this API never actually returns
    (see ``app.api.init_api`` where ``api.ERROR_SCHEMA`` is overridden to
    this class)."""

    error = fields.Nested(ErrorDetailSchema)


# ---- auth --------------------------------------------------------------


class LoginRequestSchema(Schema):
    email = fields.Email(required=True)
    password = fields.String(required=True, load_only=True)


class TokenUserSchema(Schema):
    id = fields.Integer()
    email = fields.String()
    display_name = fields.String()
    role = fields.String()


class TokenResponseSchema(Schema):
    token = fields.String()
    token_type = fields.String()
    expires_at = fields.String()
    user = fields.Nested(TokenUserSchema)


# ---- /me -----------------------------------------------------------------


class MeSchema(Schema):
    id = fields.Integer()
    email = fields.String()
    display_name = fields.String()
    role = fields.String()
    is_active = fields.Boolean()
    last_login_at = fields.String(allow_none=True)
    created_at = fields.String()


# ---- accounts --------------------------------------------------------------


class ScheduleCoreSchema(Schema):
    cron = fields.String()
    enabled = fields.Boolean()
    last_run_at = fields.String(allow_none=True)
    next_run_at = fields.String(allow_none=True)


class RunCoreSchema(Schema):
    id = fields.Integer()
    status = fields.String()
    trigger = fields.String()
    started_at = fields.String(allow_none=True)
    finished_at = fields.String(allow_none=True)
    composite_score = fields.Integer(allow_none=True)


class AccountCoreSchema(Schema):
    id = fields.Integer()
    name = fields.String()
    provider = fields.String()
    source_type = fields.String()
    created_at = fields.String()


class AccountSchema(Schema):
    """Mirrors ``account_service.AccountRow`` field-for-field."""

    account = fields.Nested(AccountCoreSchema)
    latest_run = fields.Nested(RunCoreSchema, allow_none=True)
    total_findings = fields.Integer(allow_none=True)
    critical_count = fields.Integer(allow_none=True)
    composite_score = fields.Integer(allow_none=True)
    schedule = fields.Nested(ScheduleCoreSchema, allow_none=True)


# ---- runs --------------------------------------------------------------


class RunDetailSchema(Schema):
    """The full ``Run`` row (as opposed to ``RunCoreSchema``'s summary shape
    used when nested inside an account)."""

    id = fields.Integer()
    account_id = fields.Integer()
    status = fields.String()
    trigger = fields.String()
    triggered_by = fields.Integer(allow_none=True)
    started_at = fields.String(allow_none=True)
    finished_at = fields.String(allow_none=True)
    duration_ms = fields.Integer(allow_none=True)
    progress_pct = fields.Integer()
    progress_stage = fields.String(allow_none=True)
    composite_score = fields.Integer(allow_none=True)
    error_message = fields.String(allow_none=True)
    created_at = fields.String()


class RunSchema(Schema):
    """Mirrors ``run_query.RunRow`` field-for-field."""

    run = fields.Nested(RunDetailSchema)
    account_name = fields.String()
    total_findings = fields.Integer(allow_none=True)
    critical_count = fields.Integer(allow_none=True)


# ---- findings --------------------------------------------------------------


class FindingSchema(Schema):
    """Mirrors the ``Finding`` ORM row field-for-field."""

    id = fields.Integer()
    run_id = fields.Integer()
    group_id = fields.Integer()
    check_id = fields.String()
    title = fields.String()
    severity = fields.String()
    category = fields.String()
    principal_uid = fields.String(allow_none=True)
    resource = fields.String(allow_none=True)
    policy_uid = fields.String(allow_none=True)
    risk_score = fields.Integer()
    likelihood = fields.Integer(allow_none=True)
    impact = fields.Integer(allow_none=True)
    evidence = fields.Dict(allow_none=True)
    recommendation = fields.String()
    remediation_snippet = fields.String(allow_none=True)
    compliance_tags = fields.Raw(allow_none=True)
    status = fields.String()
    created_at = fields.String()


class FindingGroupCoreSchema(Schema):
    id = fields.Integer()
    account_id = fields.Integer()
    fingerprint = fields.String()
    check_id = fields.String()
    principal_uid = fields.String(allow_none=True)
    current_status = fields.String()
    assignee_id = fields.Integer(allow_none=True)
    ticket_ref = fields.String(allow_none=True)


class ActivityItemSchema(Schema):
    kind = fields.String()
    at = fields.String()
    actor_name = fields.String()
    from_status = fields.String(allow_none=True)
    to_status = fields.String(allow_none=True)
    note = fields.String(allow_none=True)
    body = fields.String(allow_none=True)
    assign_to = fields.String(allow_none=True)


class ExceptionInfoSchema(Schema):
    kind = fields.String()
    reason = fields.String()
    expires_at = fields.String(allow_none=True)
    created_by_name = fields.String()
    created_at = fields.String()


class FindingActionSchema(Schema):
    """``(to_status, label)`` tuples from ``workflow_service.available_actions``
    — a 2-item list is the natural JSON shape for a plain tuple."""

    to_status = fields.String()
    label = fields.String()


class FindingDetailSchema(Schema):
    """Mirrors ``finding_detail.FindingDetail`` field-for-field."""

    group = fields.Nested(FindingGroupCoreSchema)
    finding = fields.Nested(FindingSchema)
    activity = fields.List(fields.Nested(ActivityItemSchema))
    assignee_name = fields.String(allow_none=True)
    exception = fields.Nested(ExceptionInfoSchema, allow_none=True)
    first_seen = fields.String(allow_none=True)
    last_seen = fields.String(allow_none=True)
    age_days = fields.Integer(allow_none=True)
    actions = fields.Method("get_actions")

    def get_actions(self, obj: object) -> list[dict[str, str]]:
        actions = getattr(obj, "actions", [])
        return [{"to_status": to, "label": label} for to, label in actions]


# ---- principals / graph --------------------------------------------------


class PrincipalSchema(Schema):
    """Mirrors ``graph_view.PrincipalBlastRow`` field-for-field."""

    principal_uid = fields.String()
    username = fields.String(allow_none=True)
    kind = fields.String()
    blast_radius_score = fields.Integer()
    reachable_actions = fields.Integer()
    reachable_sensitive = fields.Integer()


class GraphNodeSchema(Schema):
    data = fields.Dict()


class GraphEdgeSchema(Schema):
    data = fields.Dict()


class PrincipalGraphSchema(Schema):
    """Mirrors ``graph_view.principal_graph``'s returned dict."""

    focus = fields.String()
    focus_label = fields.String()
    nodes = fields.List(fields.Dict())
    edges = fields.List(fields.Dict())
    escalation_path = fields.List(fields.String(), allow_none=True)


# ---- compliance / checks ---------------------------------------------------


class ControlRowSchema(Schema):
    control_id = fields.String()
    check_ids = fields.List(fields.String())
    check_titles = fields.List(fields.String())
    passing = fields.Boolean()
    finding_count = fields.Integer()
    top_severity = fields.String(allow_none=True)


class ComplianceFrameworkSchema(Schema):
    """Mirrors ``compliance_view.FrameworkSummary`` field-for-field."""

    key = fields.String()
    label = fields.String()
    total_controls = fields.Integer()
    passing_controls = fields.Integer()
    percent = fields.Integer()
    controls = fields.List(fields.Nested(ControlRowSchema))


class CheckCatalogSchema(Schema):
    """Mirrors ``checks_catalog.CheckCatalogRow`` field-for-field."""

    check_id = fields.String()
    title = fields.String()
    category = fields.String()
    severity = fields.String()
    description = fields.String()
    remediation = fields.String()
    compliance_tags = fields.List(fields.String())
    finding_count = fields.Integer()
