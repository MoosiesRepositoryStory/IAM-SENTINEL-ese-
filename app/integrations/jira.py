"""``JiraAdapter`` (§7.5) — formats a real Jira "create issue" REST payload
(the v3 shape: ``fields.project/summary/description/issuetype``) but never
actually calls the Jira API. This is a deliberate, permanent stub, not a
"real if creds happen to be present" adapter: real Jira OAuth/API-token
auth is an explicit Phase 4 scope cut (see the project roadmap — "real
Jira/Slack OAuth" is listed as stubs-only), so there is no credentialed path
to fall into here at all. The formatted payload is still built for real and
logged, so the pattern the demo is illustrating (what WOULD be sent) is
genuine — only the network call is skipped, and the returned ref says so
plainly rather than pretending an issue was created.
"""

from __future__ import annotations

import logging

from app.integrations.base import FindingView, TicketRef

logger = logging.getLogger(__name__)


class JiraAdapter:
    kind = "jira"

    def create_ticket(
        self, finding: FindingView, config: dict, *, title: str, body: str
    ) -> TicketRef:
        project_key = (config.get("project_key") or "SEC").strip() or "SEC"
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": title,
                "description": body,
                "issuetype": {"name": "Bug"},
                "labels": ["iam-sentinel", finding.severity.lower()],
            }
        }
        logger.info("Simulated Jira issue payload for group %s: %s", finding.group_id, payload)

        # A plausible-looking key derived from the finding, not a random
        # number — same issue re-ticketed twice would look consistent, and
        # it's obviously not a real Jira sequence (Jira's own counter has no
        # relationship to this app's group ids).
        ref = f"{project_key}-{1000 + finding.group_id} (simulated)"
        return TicketRef(ref=ref, simulated=True, url=None)
