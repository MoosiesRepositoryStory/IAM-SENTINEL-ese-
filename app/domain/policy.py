"""Helpers for reading AWS-style IAM policy documents.

This is deliberately a *structural* reader, not a policy evaluation engine. As
§15 notes, full IAM evaluation (condition keys, resource-policy intersection) is
explicit non-goal / future work. We extract the shape checks need: statements,
actions, resources, and the presence of dangerous wildcards / NotAction.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def statements(document: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Return the list of statement dicts from a policy document.

    Accepts the two shapes seen in the wild: ``Statement`` as a single dict or
    as a list. Returns ``[]`` for anything malformed.
    """
    if not isinstance(document, dict):
        return []
    raw = document.get("Statement", [])
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [s for s in raw if isinstance(s, dict)]
    return []


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable):
        return [str(v) for v in value]
    return [str(value)]


def actions(statement: dict[str, Any]) -> list[str]:
    """The ``Action`` values of a statement (empty if it uses ``NotAction``)."""
    return _as_list(statement.get("Action"))


def not_actions(statement: dict[str, Any]) -> list[str]:
    return _as_list(statement.get("NotAction"))


def resources(statement: dict[str, Any]) -> list[str]:
    """The ``Resource`` values a statement applies to.

    A ``NotResource`` statement applies to *every* resource except the ones
    listed — the complement of the list, not the list itself. Returning that
    list as if it were the granted set would be a semantic inversion (the one
    resource a NotResource statement excludes is exactly the one this reader
    would report as "the" resource). This structural reader doesn't attempt
    to represent "everything except X" precisely; consistent with how
    ``NotAction`` is folded into the wildcard sentinel in
    :func:`granted_actions`, a NotResource statement is treated as unbounded
    (``["*"]``) rather than inverted.
    """
    resource = _as_list(statement.get("Resource"))
    if resource:
        return resource
    if statement.get("NotResource") is not None:
        return ["*"]
    return []


def is_allow(statement: dict[str, Any]) -> bool:
    return str(statement.get("Effect", "Allow")).lower() == "allow"


def is_assume_role_statement(statement: dict[str, Any]) -> bool:
    """Whether a trust-policy statement is an *Allow* grant of
    ``sts:AssumeRole`` (exact or ``*``-covered, case-insensitive).

    The single gate every trust-policy consumer (the permission graph's
    ``CAN_ASSUME`` edges, the trust-wildcard-principal check) must apply
    before inspecting ``Principal`` — a ``Deny`` statement or a statement
    granting an unrelated action must never be read as an assumable trust
    grant, regardless of what its ``Principal`` field says.
    """
    if not is_allow(statement):
        return False
    acts = {a.lower() for a in actions(statement)}
    return "sts:assumerole" in acts or "*" in acts


def principal_has_wildcard(principal: Any) -> bool:
    """Whether a trust statement's ``Principal`` field grants ``*`` (anyone),
    as the bare scalar ``"*"`` or inside a list-valued field, e.g.
    ``{"AWS": ["*", "arn:aws:iam::111111111111:root"]}`` — a real AWS shape
    that a plain ``"*" in principal.values()`` scan misses entirely, since a
    dict's value there is the *list*, not the string ``"*"`` itself.
    """
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for value in principal.values():
            if value == "*":
                return True
            if isinstance(value, list) and "*" in value:
                return True
    return False


def has_wildcard_action(document: dict[str, Any] | None) -> bool:
    """True if any Allow statement grants ``*`` (or ``service:*``-only ``*``)."""
    for st in statements(document):
        if not is_allow(st):
            continue
        if "*" in actions(st):
            return True
    return False


def has_wildcard_resource(document: dict[str, Any] | None) -> bool:
    for st in statements(document):
        if not is_allow(st):
            continue
        if "*" in resources(st):
            return True
    return False


def uses_not_action(document: dict[str, Any] | None) -> bool:
    return any(not_actions(st) for st in statements(document))


def granted_actions(document: dict[str, Any] | None) -> set[str]:
    """Union of concrete actions granted by Allow statements.

    ``*`` and ``NotAction`` statements are represented by the sentinel ``"*"``
    so callers can detect "grants everything" without enumerating the universe.
    """
    out: set[str] = set()
    for st in statements(document):
        if not is_allow(st):
            continue
        if not_actions(st):
            out.add("*")
            continue
        for action in actions(st):
            out.add(action)
    return out


def is_sensitive_action(action: str, sensitive_catalog: set[str]) -> bool:
    """Wildcard-aware membership test against the sensitive-action catalog.

    Matches ``*`` (everything), an exact action, or a service wildcard such as
    ``iam:*`` covering ``iam:CreateUser``.
    """
    if action == "*":
        return True
    if action in sensitive_catalog:
        return True
    if action.endswith(":*"):
        service = action[:-1]  # keep trailing colon, e.g. "iam:"
        return any(s.startswith(service) or s == "*" for s in sensitive_catalog)
    return False


def grants_action(actions: set[str], target: str) -> bool:
    """Whether a *wildcard-bearing* grant set covers a concrete ``target`` action.

    The mirror image of :func:`is_sensitive_action`: there a concrete action is
    tested against a catalog that may contain wildcards; here the roles are
    reversed — ``actions`` (e.g. a principal's granted actions, which may
    contain ``"*"`` or ``"iam:*"``) is the wildcard-bearing side, and
    ``target`` (e.g. ``"iam:PassRole"``) is always concrete. The two are *not*
    interchangeable by swapping arguments: ``is_sensitive_action`` only checks
    whether the concrete side is itself a wildcard, never whether the catalog
    side contains one covering it.
    """
    if "*" in actions or target in actions:
        return True
    service = target.split(":")[0]
    return f"{service}:*" in actions


# Curated catalog of high-blast-radius actions (§6.2). Not exhaustive by design.
SENSITIVE_ACTIONS: set[str] = {
    "*",
    "iam:*",
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PassRole",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
    "kms:Decrypt",
    "kms:*",
    "s3:*",
    "s3:GetObject",
    "s3:PutBucketPolicy",
    "ec2:RunInstances",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "secretsmanager:GetSecretValue",
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
}
