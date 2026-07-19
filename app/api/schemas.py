"""Marshmallow schemas for /api/v1 (§10.4). Slice 4a's read surface plus
Slice 4b's mutating request/response shapes.

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

**Slice 4b request bodies are JSON, not the HTML app's ``multipart/
x-www-form-urlencoded``** — the API is JSON throughout (matches 4a's read
surface and the login route already built in 4a). Where the HTML wizard reads
an uploaded file (``_read_upload`` in ``app.web.views``), it immediately
decodes it to plain UTF-8 text before ever reaching ``connect_account`` — so
JSON string fields (``inventory_text``/``policies_json``/``logs_text``) are
the exact same contract ``connect_account`` already accepts, not a lesser
substitute for a real file upload.
"""

from __future__ import annotations

from marshmallow import Schema, fields, validate

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


# ---- Slice 4b: accounts mutations ------------------------------------------


class ThresholdsSchema(Schema):
    """Mirrors ``app.domain.records.Thresholds`` — all fields optional, each
    defaulting to that dataclass's own default (also the HTML wizard's
    default, per ``views._parse_thresholds``)."""

    inactivity_days = fields.Integer(load_default=90)
    password_age_days = fields.Integer(load_default=90)
    key_age_days = fields.Integer(load_default=90)
    failed_logins = fields.Integer(load_default=5)


class ConnectAccountRequestSchema(Schema):
    """Mirrors the HTML wizard's 3-step submit (§5.3) collapsed into one JSON
    body. ``thresholds`` omitted entirely means "use the defaults"; the
    ``schedule_*`` fields are the wizard step 3's optional recurring-scan
    section (§5.5) — set ``schedule_enabled`` to create one atomically with
    the account, same as the HTML path."""

    name = fields.String(required=True)
    method = fields.String(
        load_default="demo", validate=validate.OneOf(("demo", "assume_role", "upload"))
    )
    role_arn = fields.String(load_default=None, allow_none=True)
    external_id = fields.String(load_default=None, allow_none=True)
    inventory_text = fields.String(load_default=None, allow_none=True)
    policies_json = fields.String(load_default=None, allow_none=True)
    logs_text = fields.String(load_default=None, allow_none=True)
    thresholds = fields.Nested(ThresholdsSchema, load_default=dict)
    schedule_enabled = fields.Boolean(load_default=False)
    schedule_cron = fields.String(load_default="")


class ConnectAccountResponseSchema(Schema):
    account_id = fields.Integer()
    run_id = fields.Integer()
    schedule_id = fields.Integer(allow_none=True)


class ScanResponseSchema(Schema):
    run_id = fields.Integer()


class ScheduleWriteRequestSchema(Schema):
    cron = fields.String(required=True)
    enabled = fields.Boolean(load_default=True)


class ScheduleDetailSchema(Schema):
    """The full ``Schedule`` row — distinct from the summary ``ScheduleCoreSchema``
    nested inside ``AccountSchema``, same relationship as ``RunDetailSchema``
    vs. ``RunCoreSchema`` above."""

    id = fields.Integer()
    account_id = fields.Integer()
    cron = fields.String()
    enabled = fields.Boolean()
    last_run_at = fields.String(allow_none=True)
    next_run_at = fields.String(allow_none=True)


class ScheduleRunNowResponseSchema(Schema):
    run_id = fields.Integer()


# ---- Slice 4b: findings mutations -------------------------------------------


class TransitionRequestSchema(Schema):
    to_status = fields.String(required=True)
    note = fields.String(load_default=None, allow_none=True)


class SuppressRequestSchema(Schema):
    """No ``expires_at`` — suppression is "don't show me this," not
    time-boxed (§7.4, matches ``views.finding_suppress``'s docstring)."""

    reason = fields.String(required=True)


class AcceptRiskRequestSchema(Schema):
    reason = fields.String(required=True)
    expires_at = fields.String(load_default=None, allow_none=True)


class CommentRequestSchema(Schema):
    body = fields.String(required=True)


class AssignRequestSchema(Schema):
    """Mirrors the HTML form field exactly (``views.finding_assign`` /
    ``collaboration.assign``): ``"me"`` assigns the caller, ``""``/``"none"``
    unassigns, anything else is parsed as a numeric user id."""

    assignee_id = fields.String(load_default="", allow_none=True)


# ---- Slice 4b: bulk findings mutations --------------------------------------


class BulkTransitionRequestSchema(Schema):
    group_ids = fields.List(fields.Integer(), required=True)
    to_status = fields.String(required=True)
    note = fields.String(load_default=None, allow_none=True)


class BulkAssignRequestSchema(Schema):
    group_ids = fields.List(fields.Integer(), required=True)
    assignee_id = fields.String(load_default="", allow_none=True)


class BulkSuppressRequestSchema(Schema):
    group_ids = fields.List(fields.Integer(), required=True)
    reason = fields.String(required=True)


class BulkAcceptRiskRequestSchema(Schema):
    group_ids = fields.List(fields.Integer(), required=True)
    reason = fields.String(required=True)
    expires_at = fields.String(load_default=None, allow_none=True)


class BulkFailureSchema(Schema):
    group_id = fields.Integer()
    reason = fields.String()


class BulkResultSchema(Schema):
    """Mirrors ``bulk_service.BulkResult`` — ``failed`` is a list of
    ``(group_id, reason)`` tuples on the dataclass; re-shaped to objects
    here since a bare 2-tuple doesn't have a natural JSON field-name mapping."""

    action = fields.String()
    succeeded = fields.List(fields.Integer())
    count = fields.Integer()
    failed = fields.Method("get_failed")

    def get_failed(self, obj: object) -> list[dict[str, object]]:
        failed: list[tuple[int, str]] = getattr(obj, "failed", [])
        return [{"group_id": gid, "reason": reason} for gid, reason in failed]
