"""Single source of truth for check -> compliance-control mapping (§6.5).

Kept as one auditable table so the compliance page and the per-finding
``compliance_tags`` are always in sync. Tags use the form ``FRAMEWORK:control``.
"""

from __future__ import annotations

# Human-readable framework labels for the compliance UI.
FRAMEWORKS: dict[str, str] = {
    "CIS_AWS_1.4": "CIS AWS Foundations v1.4",
    "SOC2": "SOC 2",
    "NIST": "NIST 800-53",
}

# check_id -> {framework: control_id}
_MAP: dict[str, dict[str, str]] = {
    "iam.user.mfa_disabled": {"CIS_AWS_1.4": "1.10", "SOC2": "CC6.1", "NIST": "IA-2(1)"},
    "iam.credential.old_access_key": {"CIS_AWS_1.4": "1.14", "SOC2": "CC6.1", "NIST": "IA-5(1)"},
    "iam.credential.stale_password": {"CIS_AWS_1.4": "1.9", "SOC2": "CC6.1", "NIST": "IA-5(1)"},
    "iam.user.inactive": {"CIS_AWS_1.4": "1.12", "SOC2": "CC6.2", "NIST": "AC-2(3)"},
    "iam.user.service_console_access": {"SOC2": "CC6.1", "NIST": "AC-2"},
    "iam.user.no_recent_login": {"CIS_AWS_1.4": "1.12", "SOC2": "CC6.2", "NIST": "AC-2(3)"},
    "iam.credential.unused_active": {"CIS_AWS_1.4": "1.12", "SOC2": "CC6.2", "NIST": "AC-2(3)"},
    "policy.wildcard_action": {"CIS_AWS_1.4": "1.16", "SOC2": "CC6.3", "NIST": "AC-6"},
    "policy.sensitive_action_on_star": {"CIS_AWS_1.4": "1.16", "SOC2": "CC6.3", "NIST": "AC-6(1)"},
    "policy.risky_not_action": {"CIS_AWS_1.4": "1.16", "SOC2": "CC6.3", "NIST": "AC-6"},
    "policy.overly_broad_resource": {"CIS_AWS_1.4": "1.16", "SOC2": "CC6.3", "NIST": "AC-6"},
    "iam.role.trust_wildcard_principal": {
        "CIS_AWS_1.4": "1.22",
        "SOC2": "CC6.3",
        "NIST": "AC-6(2)",
    },
    "iam.escalation.passrole_createkey": {
        "CIS_AWS_1.4": "1.16",
        "SOC2": "CC6.3",
        "NIST": "AC-6(9)",
    },
    "iam.principal.admin_access": {"CIS_AWS_1.4": "1.16", "SOC2": "CC6.3", "NIST": "AC-6(5)"},
    "iam.least_privilege.unused_grants": {"SOC2": "CC6.3", "NIST": "AC-6(1)"},
    "log.repeated_login_failures": {"CIS_AWS_1.4": "4.1", "SOC2": "CC7.2", "NIST": "AC-7"},
    "log.privileged_login": {"CIS_AWS_1.4": "4.1", "SOC2": "CC7.2", "NIST": "AU-6"},
    "log.service_interactive_login": {"SOC2": "CC7.2", "NIST": "AU-6"},
    "log.denied_sensitive_iam": {"CIS_AWS_1.4": "4.4", "SOC2": "CC7.2", "NIST": "AU-6"},
    "inventory.orphaned_principal": {"SOC2": "CC6.2", "NIST": "AC-2"},
}


def compliance_tags_for(check_id: str) -> list[str]:
    """Return ``["FRAMEWORK:control", ...]`` tags for a check id."""
    mapping = _MAP.get(check_id, {})
    return [f"{framework}:{control}" for framework, control in mapping.items()]


def frameworks_for(check_id: str) -> set[str]:
    return set(_MAP.get(check_id, {}).keys())


def framework_controls() -> dict[str, dict[str, list[str]]]:
    """Invert ``_MAP`` into ``{framework: {control_id: [check_id, ...]}}`` —
    the shape the compliance page rolls up (§6.5, Phase 3 Slice 4). A
    control's existence and check membership come entirely from this static
    table, not from what fired on any particular run, so a clean run still
    shows every control explicitly rather than omitting it."""
    out: dict[str, dict[str, list[str]]] = {}
    for check_id, fw_map in _MAP.items():
        for framework, control in fw_map.items():
            out.setdefault(framework, {}).setdefault(control, []).append(check_id)
    return out
