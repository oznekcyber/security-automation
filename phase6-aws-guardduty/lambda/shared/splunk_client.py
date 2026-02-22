"""
Splunk HEC Client — shared module for GuardDuty Lambda responders.

Ships GuardDuty findings to Splunk HTTP Event Collector using the same
pattern as the Phase 2 Splunk Log Ingestion Pipeline.

Environment variables (populated from SSM Parameter Store):
    SPLUNK_HEC_URL    — Full URL to Splunk HEC endpoint, e.g. https://splunk:8088/services/collector
    SPLUNK_HEC_TOKEN  — Splunk HEC token
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

_RETRY = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
_TIMEOUT = 10  # seconds


def _get_session() -> requests.Session:
    session = requests.Session()
    session.mount("http://", HTTPAdapter(max_retries=_RETRY))
    session.mount("https://", HTTPAdapter(max_retries=_RETRY))
    return session


def ship_finding(finding: dict[str, Any], automated_actions: list[str] | None = None) -> dict[str, Any]:
    """
    Ship a GuardDuty finding to Splunk HEC.

    Args:
        finding:           Raw GuardDuty finding dict.
        automated_actions: List of automated action descriptions taken by the responder.

    Returns:
        Splunk HEC API response dict, or empty dict if HEC is not configured.

    Raises:
        requests.HTTPError: If Splunk returns a non-2xx response.
    """
    hec_url = os.environ.get("SPLUNK_HEC_URL", "")
    hec_token = os.environ.get("SPLUNK_HEC_TOKEN", "")

    if not hec_url or not hec_token:
        logger.warning("SPLUNK_HEC_URL or SPLUNK_HEC_TOKEN not set — skipping Splunk shipping")
        return {}

    # Normalize the HEC URL
    if not hec_url.endswith("/services/collector"):
        hec_url = hec_url.rstrip("/") + "/services/collector"

    finding_id = finding.get("id", "unknown")
    finding_type = finding.get("type", "Unknown")

    event_payload = {
        "time": int(time.time()),
        "sourcetype": "aws:guardduty:finding",
        "source": "aws:guardduty",
        "index": "security",
        "event": {
            **finding,
            "_automated_actions": automated_actions or [],
            "_pipeline_version": "phase6",
        },
    }

    session = _get_session()
    headers = {
        "Authorization": f"Splunk {hec_token}",
        "Content-Type": "application/json",
    }

    logger.info("Shipping finding %s (type=%s) to Splunk HEC", finding_id, finding_type)
    # Default to verifying SSL certificates.  Set SPLUNK_CA_BUNDLE to a CA bundle path for
    # self-signed certs, or set SPLUNK_DISABLE_SSL_VERIFY=true ONLY in isolated lab environments.
    ssl_verify: str | bool
    ca_bundle = os.environ.get("SPLUNK_CA_BUNDLE", "")
    if ca_bundle:
        ssl_verify = ca_bundle
    elif os.environ.get("SPLUNK_DISABLE_SSL_VERIFY", "").lower() == "true":
        ssl_verify = False
        logger.warning("SSL verification disabled for Splunk HEC — do not use in production")
    else:
        ssl_verify = True
    response = session.post(
        hec_url,
        json=event_payload,
        headers=headers,
        timeout=_TIMEOUT,
        verify=ssl_verify,
    )
    response.raise_for_status()
    result = response.json()
    logger.info("Splunk HEC response: %s", result)
    return result
