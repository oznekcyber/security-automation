"""
AbuseIPDB v2 API collector for Security Alert Normalizer.

Only IP address lookups are supported (AbuseIPDB has no file hash
endpoint).

Rate limiting
-------------
The free tier allows 1 000 checks/day.  We propagate HTTP 429 errors
as a ``RuntimeError`` with a clear message rather than silently
dropping indicators.

Authentication
--------------
AbuseIPDB uses a ``Key`` header — API key supplied directly, no
bearer-token flow needed.
"""

from __future__ import annotations

import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.utils.config import Config
from src.utils.logger import get_logger

logger = get_logger(__name__)

_ABUSE_BASE = "https://api.abuseipdb.com/api/v2"


def _build_session(cfg: Config) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=cfg.max_retries,
        backoff_factor=cfg.retry_backoff_factor,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.headers.update(
        {
            "Key": cfg.abuseipdb_api_key,
            "Accept": "application/json",
        }
    )
    return session


def fetch_ip_report(ip: str, cfg: Config, max_age_days: int = 90) -> dict[str, Any]:
    """
    Fetch an AbuseIPDB report for an IP address.

    Args:
        ip:           IPv4 or IPv6 address string.
        cfg:          Application configuration.
        max_age_days: Only include reports from the last N days (default 90).

    Returns:
        Raw AbuseIPDB API JSON response dict.

    Raises:
        PermissionError: If the API key is invalid (HTTP 401/403).
        RuntimeError:    If rate-limited and retries are exhausted.
    """
    url = f"{_ABUSE_BASE}/check"
    session = _build_session(cfg)
    params = {
        "ipAddress": ip,
        "maxAgeInDays": max_age_days,
        "verbose": "",  # include reports list for category context
    }

    logger.info("Fetching AbuseIPDB report for %s", ip)

    for attempt in range(cfg.max_retries + 1):
        logger.debug("GET %s for %s (attempt %d/%d)", url, ip, attempt + 1, cfg.max_retries + 1)
        try:
            resp = session.get(url, params=params, timeout=cfg.request_timeout)
        except requests.exceptions.Timeout:
            logger.warning("Timeout fetching AbuseIPDB for %s", ip)
            raise
        except requests.exceptions.ConnectionError as exc:
            logger.error("Connection error fetching AbuseIPDB for %s: %s", ip, exc)
            raise

        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError as exc:
                raise ValueError(
                    f"AbuseIPDB returned non-JSON body for {ip}: {exc}"
                ) from exc

        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 60))
            logger.warning(
                "AbuseIPDB rate limit hit for %s. Sleeping %ds (attempt %d/%d)",
                ip,
                retry_after,
                attempt + 1,
                cfg.max_retries + 1,
            )
            time.sleep(retry_after)
            continue

        if resp.status_code in (401, 403):
            raise PermissionError(
                f"AbuseIPDB API key rejected (HTTP {resp.status_code})."
            )

        if resp.status_code == 422:
            logger.warning(
                "AbuseIPDB rejected %s as invalid (HTTP 422) — skipping", ip
            )
            return {}

        resp.raise_for_status()

    raise RuntimeError(
        f"AbuseIPDB request for {ip} failed after {cfg.max_retries + 1} "
        "attempts (rate-limited)"
    )
