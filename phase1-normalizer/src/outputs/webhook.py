"""
Webhook output channel for Security Alert Normalizer.

POSTs the normalized alert payload to an arbitrary webhook URL.
Webhook.site is the canonical mock receiver during development, but
any HTTP endpoint that accepts JSON works.

The payload format is intentionally SOAR-friendly:
    {
        "schema_version": "1.0",
        "alert_count": <int>,
        "alerts": [ <NormalizedAlert dicts> ]
    }

Retries on transient failures (5xx) but not on 4xx, which almost
always indicate a misconfigured endpoint URL.
"""

from __future__ import annotations

import json
import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.utils.logger import get_logger

logger = get_logger(__name__)

_SCHEMA_VERSION = "1.0"


def _build_session(max_retries: int, backoff_factor: float) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def send_webhook(
    alerts: list[dict[str, Any]],
    webhook_url: str,
    timeout: int = 30,
    max_retries: int = 3,
    backoff_factor: float = 1.5,
) -> bool:
    """
    POST normalized alerts to a webhook endpoint.

    Args:
        alerts:        List of ``NormalizedAlert.to_dict()`` dicts.
        webhook_url:   Target URL (e.g., https://webhook.site/<uuid>).
        timeout:       Request timeout in seconds.
        max_retries:   Number of retry attempts on transient failures.
        backoff_factor: Exponential back-off multiplier between retries.

    Returns:
        ``True`` if the webhook accepted the payload (2xx response).
        ``False`` if the request failed after all retries.
    """
    if not webhook_url:
        logger.info("No webhook URL configured — skipping webhook delivery")
        return False

    payload: dict[str, Any] = {
        "schema_version": _SCHEMA_VERSION,
        "alert_count": len(alerts),
        "alerts": alerts,
    }

    session = _build_session(max_retries, backoff_factor)
    headers = {"Content-Type": "application/json"}

    logger.info(
        "POSTing %d alert(s) to webhook %s", len(alerts), webhook_url
    )

    for attempt in range(max_retries + 1):
        try:
            resp = session.post(
                webhook_url,
                data=json.dumps(payload, default=str),
                headers=headers,
                timeout=timeout,
            )
        except requests.exceptions.Timeout:
            logger.warning(
                "Webhook POST timed out (attempt %d/%d)", attempt + 1, max_retries + 1
            )
            if attempt < max_retries:
                time.sleep(backoff_factor ** (attempt + 1))
            continue
        except requests.exceptions.ConnectionError as exc:
            logger.error("Webhook connection error: %s", exc)
            return False

        if resp.ok:
            logger.info(
                "Webhook delivery successful (HTTP %d) to %s",
                resp.status_code,
                webhook_url,
            )
            return True

        if 400 <= resp.status_code < 500:
            logger.error(
                "Webhook rejected payload (HTTP %d) — check your URL",
                resp.status_code,
            )
            return False

        logger.warning(
            "Webhook returned HTTP %d (attempt %d/%d)",
            resp.status_code,
            attempt + 1,
            max_retries + 1,
        )

    logger.error(
        "Webhook delivery failed after %d attempts to %s",
        max_retries + 1,
        webhook_url,
    )
    return False
