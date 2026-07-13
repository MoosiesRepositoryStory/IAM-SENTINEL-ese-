"""File ingestion adapter — CSV inventory + JSON policies + auth log (§5.1).

The CSV column contract (kept from the original tool):

    username,email,role,mfa_enabled,last_login,password_last_changed,
    access_key_age_days,account_type,active,console_access,policies

``policies`` is a ``;``/``|``/``,``-separated list of policy names that must
resolve against the policies JSON file. The policies JSON is either a list of
``{"name","kind","document"}`` objects or a ``{name: document}`` mapping.

``source_config`` accepts file paths (``inventory_path`` / ``policies_path`` /
``logs_path``) and/or inline content (``inventory_text`` / ``policies_json`` /
``logs_text``) so the same adapter serves the CLI and the web upload form.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from app.ingestion.base import ProgressReporter, RawDataset, register_adapter

_TRUE = {"1", "true", "yes", "y", "on", "enabled"}
_POLICY_SEPARATORS = [";", "|", ","]


def _to_bool(value: Any) -> bool:
    return str(value).strip().lower() in _TRUE


def _to_int(value: Any) -> int | None:
    text = str(value).strip()
    if not text or text.lower() in {"none", "null", "n/a", "-"}:
        return None
    try:
        return int(float(text))
    except ValueError:
        return None


def _split_policies(value: str) -> list[str]:
    if not value:
        return []
    text = value.strip()
    for sep in _POLICY_SEPARATORS:
        if sep in text:
            return [part.strip() for part in text.split(sep) if part.strip()]
    return [text] if text else []


def _read(source_config: dict[str, Any], path_key: str, text_key: str) -> str | None:
    if source_config.get(text_key) is not None:
        return str(source_config[text_key])
    path = source_config.get(path_key)
    if path:
        return Path(path).read_text(encoding="utf-8")
    return None


class FileIngestionAdapter:
    source_type = "file"

    def fetch(self, source_config: dict[str, Any], progress: ProgressReporter) -> RawDataset:
        progress.update(10, "Reading inventory")
        principals, attachments = self._load_inventory(
            _read(source_config, "inventory_path", "inventory_text") or ""
        )

        progress.update(40, "Reading policies")
        policies_raw = _read(source_config, "policies_path", "policies_json")
        policies = self._load_policies(policies_raw)

        progress.update(70, "Reading logs")
        logs_text = _read(source_config, "logs_path", "logs_text") or ""
        log_events = self._load_logs(logs_text)

        progress.update(90, "Normalizing")
        return RawDataset(
            principals=principals,
            policies=policies,
            log_events=log_events,
            attachments=attachments,
        )

    # -- loaders --------------------------------------------------------------
    def _load_inventory(self, text: str) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
        principals: list[dict[str, Any]] = []
        attachments: list[tuple[str, str]] = []
        if not text.strip():
            return principals, attachments
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            username = (row.get("username") or "").strip()
            if not username:
                continue
            uid = (row.get("arn") or f"user/{username}").strip()
            policy_names = _split_policies(row.get("policies", ""))
            principals.append(
                {
                    "principal_uid": uid,
                    "kind": (row.get("kind") or "user").strip() or "user",
                    "username": username,
                    "email": (row.get("email") or "").strip() or None,
                    "arn": (row.get("arn") or "").strip() or None,
                    "role": (row.get("role") or "").strip() or None,
                    "account_type": (row.get("account_type") or "human").strip() or "human",
                    "active": _to_bool(row.get("active", "true")),
                    "console_access": _to_bool(row.get("console_access", "false")),
                    "mfa_enabled": _to_bool(row.get("mfa_enabled", "false")),
                    "last_login": (row.get("last_login") or "").strip() or None,
                    "password_last_changed": (row.get("password_last_changed") or "").strip()
                    or None,
                    "access_key_age_days": _to_int(row.get("access_key_age_days")),
                    "attached_policy_uids": policy_names,
                    "raw": dict(row),
                }
            )
            for name in policy_names:
                attachments.append((uid, name))
        return principals, attachments

    def _load_policies(self, raw: str | None) -> list[dict[str, Any]]:
        if not raw or not raw.strip():
            return []
        data = json.loads(raw)
        policies: list[dict[str, Any]] = []
        if isinstance(data, dict):
            # {name: document} mapping.
            for name, document in data.items():
                policies.append({"policy_uid": name, "name": name, "document": document})
        elif isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                name = item.get("name") or item.get("policy_uid")
                if not name:
                    continue
                policies.append(
                    {
                        "policy_uid": item.get("policy_uid") or name,
                        "name": name,
                        "kind": item.get("kind"),
                        "document": item.get("document") or item.get("PolicyDocument") or {},
                    }
                )
        return policies

    def _load_logs(self, text: str) -> list[dict[str, Any]]:
        # Defer parsing to the domain parser during normalization; here we just
        # pass raw lines through so the adapter stays I/O-only.
        return [{"line": line} for line in text.splitlines() if line.strip()]


register_adapter(FileIngestionAdapter())
