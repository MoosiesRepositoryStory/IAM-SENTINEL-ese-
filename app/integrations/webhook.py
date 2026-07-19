"""``WebhookAdapter`` (§7.5) — the one REAL adapter: POSTs a JSON payload to
whatever URL a target is configured with. Works against any system that can
receive a JSON POST, which is the point of a generic webhook (no vendor SDK,
no OAuth). Uses stdlib ``urllib.request`` rather than adding a ``requests``
dependency — a single JSON POST with a timeout doesn't need it, and it keeps
this adapter available in the base install (no extra to gate it behind, same
posture as every other always-on module in ``app.integrations``).
"""

from __future__ import annotations

import json
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.integrations.base import FindingView, IntegrationError, TicketRef

TIMEOUT_SECONDS = 5


class WebhookAdapter:
    kind = "webhook"

    def create_ticket(
        self, finding: FindingView, config: dict, *, title: str, body: str
    ) -> TicketRef:
        url = (config.get("url") or "").strip()
        if not url:
            raise IntegrationError("Webhook target has no URL configured.")

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
        request = Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "iam-sentinel-webhook/1"},
        )
        try:
            with urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310 — target is admin-configured, not user input
                status = response.status
        except HTTPError as exc:
            raise IntegrationError(f"Webhook target responded with HTTP {exc.code}.") from exc
        except URLError as exc:
            raise IntegrationError(f"Could not reach webhook target: {exc.reason}") from exc

        if status >= 300:
            raise IntegrationError(f"Webhook target responded with HTTP {status}.")
        return TicketRef(ref=ref, simulated=False, url=None)
