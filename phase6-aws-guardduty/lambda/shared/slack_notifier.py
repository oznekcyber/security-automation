"""
Slack Notifier — shared module for GuardDuty Lambda responders.

Posts a formatted Slack message with finding details and automated
actions taken.

Environment variables:
    SLACK_WEBHOOK_URL — Incoming webhook URL for the security channel
"""

from __future__ import annotations

import logging
import os
from typing import Any

import requests

logger = logging.getLogger(__name__)

_TIMEOUT = 5  # seconds — Slack is best-effort, don't hold up the response


def _severity_color(severity: float) -> str:
    """Return a Slack attachment color hex code based on GuardDuty severity."""
    if severity >= 7.0:
        return "#FF0000"  # Red — High/Critical
    if severity >= 4.0:
        return "#FF8C00"  # Orange — Medium
    return "#FFD700"  # Yellow — Low


def notify(
    finding: dict[str, Any],
    automated_actions: list[str] | None = None,
    error_message: str | None = None,
) -> bool:
    """
    Post a Slack notification for a GuardDuty finding.

    Args:
        finding:           Raw GuardDuty finding dict.
        automated_actions: List of human-readable automated action descriptions.
        error_message:     Optional error message if the response partially failed.

    Returns:
        True if the message was sent successfully, False otherwise.
    """
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if not webhook_url:
        logger.warning("SLACK_WEBHOOK_URL not set — skipping Slack notification")
        return False

    finding_type = finding.get("type", "Unknown")
    finding_id = finding.get("id", "unknown")
    severity = finding.get("severity", 0.0)
    account_id = finding.get("accountId", "unknown")
    region = finding.get("region", "unknown")
    description = finding.get("description", "No description available")

    actions_text = "\n".join(f"• {a}" for a in (automated_actions or [])) or "No automated actions taken"

    status_emoji = "🔴" if severity >= 7.0 else "🟠" if severity >= 4.0 else "🟡"
    error_block = (
        [{"type": "section", "text": {"type": "mrkdwn", "text": f"⚠️ *Partial failure:* {error_message}"}}]
        if error_message
        else []
    )

    payload = {
        "attachments": [
            {
                "color": _severity_color(severity),
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{status_emoji} GuardDuty Finding — {finding_type}",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Finding ID:*\n`{finding_id}`"},
                            {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                            {"type": "mrkdwn", "text": f"*Account:*\n`{account_id}`"},
                            {"type": "mrkdwn", "text": f"*Region:*\n`{region}`"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*Description:*\n{description}"},
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*Automated Actions Taken:*\n{actions_text}"},
                    },
                    *error_block,
                    {"type": "divider"},
                ],
            }
        ]
    }

    try:
        response = requests.post(webhook_url, json=payload, timeout=_TIMEOUT)
        response.raise_for_status()
        logger.info("Slack notification sent for finding %s", finding_id)
        return True
    except requests.RequestException as exc:
        logger.warning("Slack notification failed: %s", exc)
        return False
