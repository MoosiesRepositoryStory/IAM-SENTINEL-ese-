"""``WebhookAdapter`` (§7.5) — the one REAL adapter: POSTs a JSON payload to
whatever URL a target is configured with. Works against any system that can
receive a JSON POST, which is the point of a generic webhook (no vendor SDK,
no OAuth). Uses stdlib ``http.client`` rather than adding a ``requests``
dependency — this keeps the adapter available in the base install (no extra
to gate it behind, same posture as every other always-on module in
``app.integrations``).

Destination validation + DNS pinning lives in ``app.integrations.net_safety``
— see that module's docstring for why an admin-configured URL still needs an
SSRF guard in this app specifically (a public deployment hands out a shared
admin login, per docs/ARCHITECTURE_SPEC.md §13.6).
"""

from __future__ import annotations

import json
import uuid

from app.integrations.base import FindingView, IntegrationError, TicketRef
from app.integrations.net_safety import (
    CONNECT_TIMEOUT_SECONDS,
    MAX_RESPONSE_BYTES,
    open_pinned_connection,
    resolve_pinned_ip,
    resolve_safe_target,
)


class WebhookAdapter:
    kind = "webhook"

    def create_ticket(
        self, finding: FindingView, config: dict, *, title: str, body: str
    ) -> TicketRef:
        url = (config.get("url") or "").strip()
        if not url:
            raise IntegrationError("Webhook target has no URL configured.")

        scheme, hostname, port, path = resolve_safe_target(url)
        pinned_ip = resolve_pinned_ip(hostname)

        # Generated here (not by the receiver) so the caller has a stable
        # correlation id even if the destination system doesn't echo one
        # back — sent as part of the payload so the receiving side can key
        # off it too.
        ref = f"webhook-{uuid.uuid4().hex[:10]}"
        payload = {
            "ref": ref,
            "title": title,
            "body": body,
            "finding": {
                "group_id": finding.group_id,
                "check_id": finding.check_id,
                "severity": finding.severity,
                "category": finding.category,
                "principal_uid": finding.principal_uid,
                "resource": finding.resource,
                "recommendation": finding.recommendation,
                "url": finding.finding_url,
            },
        }
        data = json.dumps(payload).encode("utf-8")

        connection = open_pinned_connection(scheme, hostname, port, pinned_ip, CONNECT_TIMEOUT_SECONDS)
        try:
            connection.request(
                "POST", path, body=data,
                headers={"Content-Type": "application/json", "User-Agent": "iam-sentinel-webhook/1"},
            )
            response = connection.getresponse()
            status = response.status
            response.read(MAX_RESPONSE_BYTES + 1)  # bounded; body itself is unused
        except OSError as exc:
            raise IntegrationError(f"Could not reach webhook target: {exc}") from exc
        finally:
            connection.close()

        if status >= 300:
            raise IntegrationError(f"Webhook target responded with HTTP {status}.")
        return TicketRef(ref=ref, simulated=False, url=None)
