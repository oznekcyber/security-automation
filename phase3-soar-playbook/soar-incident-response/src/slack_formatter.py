"""
Slack Block Kit notification formatter for SOAR incident alerts.

This module builds rich Slack messages using the Block Kit format so that
security analysts receive a well-structured, actionable notification in their
incident-response channel — not a wall of raw JSON.

Design decisions
----------------
* Block Kit ``attachments`` colour field drives the sidebar colour that Slack
  displays — this gives analysts an immediate visual cue about severity.
* Action buttons include direct links to TheHive (if a case URL is known)
  and Escalate / Close buttons that can be wired to additional Shuffle steps
  via Slack's Interactivity API.
* The IOC section is intentionally truncated at five items per type to keep
  the message readable; the full list lives in the TheHive case.

Colour mapping
--------------
  danger  (red)    → CRITICAL, HIGH
  warning (yellow) → MEDIUM
  good    (green)  → LOW, INFO

Usage
-----
::

    formatter = SlackFormatter()
    message = formatter.format(
        alert_title="Phishing campaign from evil.ru",
        score_result={"score": 8.2, "tier": "CRITICAL", "decision": "auto-escalate"},
        iocs={"ips": ["185.220.101.42"], ...},
        thehive_case_url="https://thehive.example.com/cases/~123456",
    )
    # message is a dict ready for requests.post(SLACK_WEBHOOK_URL, json=message)
"""

from __future__ import annotations

from typing import Any


_TIER_COLOUR: dict[str, str] = {
    "CRITICAL": "danger",
    "HIGH": "danger",
    "MEDIUM": "warning",
    "LOW": "good",
    "INFO": "good",
}

_TIER_EMOJI: dict[str, str] = {
    "CRITICAL": ":rotating_light:",
    "HIGH": ":red_circle:",
    "MEDIUM": ":large_yellow_circle:",
    "LOW": ":large_green_circle:",
    "INFO": ":white_circle:",
}

_DECISION_EMOJI: dict[str, str] = {
    "auto-escalate": ":arrow_double_up:",
    "analyst-review": ":eyes:",
    "auto-close": ":white_check_mark:",
}

# Maximum IOCs to display per type before truncating
_MAX_IOC_DISPLAY = 5


class SlackFormatter:
    """
    Build Slack Block Kit payloads for SOAR incident notifications.

    All public methods return dicts that can be posted directly to a
    Slack Incoming Webhook URL.
    """

    def format(
        self,
        alert_title: str,
        score_result: dict[str, Any],
        iocs: dict[str, Any],
        thehive_case_url: str | None = None,
        enrichment_summary: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Build a complete Slack Block Kit message dict.

        Args:
            alert_title:        Short alert title string.
            score_result:       Dict from :class:`EnrichmentScorer`.
            iocs:               Dict from :class:`IOCExtractor`.
            thehive_case_url:   Optional URL to the created TheHive case.
            enrichment_summary: Optional condensed enrichment data for display.

        Returns:
            Dict suitable for ``requests.post(SLACK_WEBHOOK_URL, json=<result>)``.
        """
        tier: str = score_result.get("tier", "INFO")
        score: float = score_result.get("score", 0.0)
        decision: str = score_result.get("decision", "auto-close")
        colour = _TIER_COLOUR.get(tier, "good")
        tier_emoji = _TIER_EMOJI.get(tier, ":white_circle:")
        decision_emoji = _DECISION_EMOJI.get(decision, "")

        blocks: list[dict[str, Any]] = []

        # ------------------------------------------------------------------
        # Header block
        # ------------------------------------------------------------------
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{tier_emoji} SOAR Alert: {alert_title}",
                "emoji": True,
            },
        })

        # ------------------------------------------------------------------
        # Summary section
        # ------------------------------------------------------------------
        blocks.append({
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Risk Score*\n`{score}/10` — *{tier}*",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*SOAR Decision*\n{decision_emoji} `{decision}`",
                },
            ],
        })

        blocks.append({"type": "divider"})

        # ------------------------------------------------------------------
        # IOC section
        # ------------------------------------------------------------------
        ioc_lines: list[str] = []

        for ioc_key, label in [
            ("ips", "IPs"),
            ("urls", "URLs"),
            ("domains", "Domains"),
            ("hashes", "Hashes"),
            ("emails", "Emails"),
        ]:
            items = iocs.get(ioc_key, [])
            if not items:
                continue
            display_items = items[:_MAX_IOC_DISPLAY]
            remaining = len(items) - len(display_items)

            formatted: list[str] = []
            for item in display_items:
                if isinstance(item, dict):
                    formatted.append(f"`{item['value']}` ({item['type']})")
                else:
                    formatted.append(f"`{item}`")

            ioc_lines.append(f"*{label}:* " + ", ".join(formatted))
            if remaining > 0:
                ioc_lines.append(f"_…and {remaining} more (see TheHive case)_")

        if ioc_lines:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Extracted IOCs*\n" + "\n".join(ioc_lines),
                },
            })
            blocks.append({"type": "divider"})

        # ------------------------------------------------------------------
        # Enrichment details section
        # ------------------------------------------------------------------
        if enrichment_summary:
            enrich_lines: list[str] = []
            vt = enrichment_summary.get("vt_result", {})
            abuse = enrichment_summary.get("abuse_result", {})
            if vt:
                mal = vt.get("malicious", "N/A")
                total = vt.get("total", "N/A")
                rep = vt.get("reputation", "N/A")
                enrich_lines.append(
                    f"*VirusTotal:* {mal}/{total} engines malicious, reputation {rep}"
                )
            if abuse:
                conf = abuse.get("confidence", "N/A")
                reports = abuse.get("total_reports", "N/A")
                enrich_lines.append(
                    f"*AbuseIPDB:* {conf}% confidence, {reports} reports"
                )
            if enrich_lines:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Enrichment Summary*\n" + "\n".join(enrich_lines),
                    },
                })
                blocks.append({"type": "divider"})

        # ------------------------------------------------------------------
        # Action buttons
        # ------------------------------------------------------------------
        actions: list[dict[str, Any]] = [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": ":arrow_double_up: Escalate", "emoji": True},
                "style": "danger",
                "value": "escalate",
                "action_id": "soar_escalate",
            },
            {
                "type": "button",
                "text": {"type": "plain_text", "text": ":white_check_mark: Close", "emoji": True},
                "style": "primary",
                "value": "close",
                "action_id": "soar_close",
            },
        ]

        if thehive_case_url:
            actions.append({
                "type": "button",
                "text": {"type": "plain_text", "text": ":mag: View in TheHive", "emoji": True},
                "url": thehive_case_url,
                "action_id": "soar_view_thehive",
            })

        blocks.append({
            "type": "actions",
            "elements": actions,
        })

        # ------------------------------------------------------------------
        # Wrap in attachments for colour sidebar
        # ------------------------------------------------------------------
        return {
            "text": f"[{tier}] SOAR Alert: {alert_title}",  # fallback text
            "attachments": [
                {
                    "color": colour,
                    "blocks": blocks,
                }
            ],
        }
