"""
TheHive Client — shared module for GuardDuty Lambda responders.

Creates a TheHive case for every GuardDuty finding, using the same
HTTP pattern as Phase 4.  All configuration is read from environment
variables loaded from SSM at Lambda cold-start.

Environment variables (populated from SSM Parameter Store):
    THEHIVE_URL      — Base URL of the TheHive 5 instance, e.g. http://thehive:9000
    THEHIVE_API_KEY  — Bearer token API key
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# Retry config — fast, as Lambda has a 30-second budget
_RETRY = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
_TIMEOUT = 10  # seconds


def _get_session() -> requests.Session:
    session = requests.Session()
    session.mount("http://", HTTPAdapter(max_retries=_RETRY))
    session.mount("https://", HTTPAdapter(max_retries=_RETRY))
    return session


def _severity_to_thehive(guardduty_severity: float) -> int:
    """Map GuardDuty severity (1-9) to TheHive severity (1-3)."""
    if guardduty_severity >= 7.0:
        return 3  # High
    if guardduty_severity >= 4.0:
        return 2  # Medium
    return 1  # Low


def create_case(finding: dict[str, Any]) -> dict[str, Any]:
    """
    Create a TheHive case from a GuardDuty finding dict.

    Args:
        finding: The raw GuardDuty finding (detail field from EventBridge event).

    Returns:
        TheHive API response dict.

    Raises:
        requests.HTTPError: If TheHive returns a non-2xx response.
        requests.RequestException: On network errors.
    """
    url = os.environ.get("THEHIVE_URL", "").rstrip("/")
    api_key = os.environ.get("THEHIVE_API_KEY", "")

    if not url or not api_key:
        logger.warning("THEHIVE_URL or THEHIVE_API_KEY not set — skipping TheHive case creation")
        return {}

    finding_type = finding.get("type", "Unknown")
    finding_id = finding.get("id", "unknown")
    severity = finding.get("severity", 5.0)
    account_id = finding.get("accountId", "unknown")
    region = finding.get("region", "unknown")

    case_payload = {
        "title": f"[GuardDuty] {finding_type} — Account {account_id}",
        "description": (
            f"**Finding ID:** {finding_id}\n"
            f"**Type:** {finding_type}\n"
            f"**Severity:** {severity}\n"
            f"**Region:** {region}\n"
            f"**Account:** {account_id}\n\n"
            f"**Description:** {finding.get('description', 'N/A')}\n\n"
            f"**Full Finding:**\n```json\n{json.dumps(finding, indent=2)}\n```"
        ),
        "severity": _severity_to_thehive(severity),
        "tags": [
            "guardduty",
            f"finding-type:{finding_type}",
            f"account:{account_id}",
            f"region:{region}",
            "automated-response",
        ],
        "flag": True,
        "status": "New",
        "tlp": 2,
    }

    session = _get_session()
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    logger.info("Creating TheHive case for finding %s (type=%s)", finding_id, finding_type)
    response = session.post(
        f"{url}/api/v1/case",
        json=case_payload,
        headers=headers,
        timeout=_TIMEOUT,
    )
    response.raise_for_status()
    result = response.json()
    logger.info("TheHive case created: %s", result.get("_id", "unknown"))
    return result
