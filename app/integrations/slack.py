"""``SlackAdapter`` (§7.5) — formats a real Slack Block Kit message payload
but never actually posts it, for the same reason as ``JiraAdapter`` (see its
docstring): real Slack OAuth/bot-token auth is a Phase 4 scope cut, so this
is a permanent, honest stub rather than a conditionally-real one.
"""

from __future__ import annotations

import logging

from app.integrations.base import FindingView, TicketRef

logger = logging.getLogger(__name__)

_SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}


class SlackAdapter:
    kind = "slack"

    def create_ticket(
        self, finding: FindingView, config: dict, *, title: str, body: str
    ) -> TicketRef:
        channel = (config.get("channel") or "#security-alerts").strip() or "#security-alerts"
        emoji = _SEVERITY_EMOJI.get(finding.severity, "⚪")
        payload = {
            "channel": channel,
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": f"{emoji} {title}"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": body}},
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": (
                                f"*Severity:* {finding.severity} · *Check:* {finding.check_id}"
                                + (f" · *Principal:* `{finding.principal_uid}`" if finding.principal_uid else "")
                            ),
                        }
                    ],
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "View finding"},
                            "url": finding.finding_url,
                        }
                    ],
                },
            ],
        }
        logger.info("Simulated Slack message payload for group %s: %s", finding.group_id, payload)

        ref = f"slack:{channel}:sim-{finding.group_id} (simulated)"
        return TicketRef(ref=ref, simulated=True, url=None)
