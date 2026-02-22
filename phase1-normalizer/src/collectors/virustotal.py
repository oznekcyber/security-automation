"""
VirusTotal v3 API collector for Security Alert Normalizer.

Handles both IP address lookups (``/api/v3/ip_addresses/{ip}``) and
file hash lookups (``/api/v3/files/{hash}``).

Rate limiting
-------------
The free VT API tier allows 4 requests/minute and 500 requests/day.
We implement exponential back-off on HTTP 429 responses and log a
clear message so the operator knows what's happening.

Authentication
--------------
VT uses a simple ``x-apikey`` header — no OAuth, no token refresh.
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

_VT_BASE = "https://www.virustotal.com/api/v3"


def _build_session(cfg: Config) -> requests.Session:
    """
    Build an ``requests.Session`` with retry logic baked in.

    We retry on connection errors and 5xx responses, but *not* on 429
    (rate-limit) because urllib3's Retry won't honour Retry-After; we
    handle 429 manually in the fetch methods below.
    """
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
    session.headers.update({"x-apikey": cfg.virustotal_api_key})
    return session


def _get_with_rate_limit(
    session: requests.Session,
    url: str,
    timeout: int,
    max_retries: int,
) -> dict[str, Any]:
    """
    Perform a GET request, sleeping when the API rate-limits us.

    Returns the parsed JSON dict.  Raises on non-recoverable errors.
    """
    for attempt in range(max_retries + 1):
        logger.debug("GET %s (attempt %d/%d)", url, attempt + 1, max_retries + 1)
        try:
            resp = session.get(url, timeout=timeout)
        except requests.exceptions.Timeout:
            logger.warning("Timeout fetching %s", url)
            raise
        except requests.exceptions.ConnectionError as exc:
            logger.error("Connection error fetching %s: %s", url, exc)
            raise

        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError as exc:
                raise ValueError(
                    f"VT returned non-JSON body for {url}: {exc}"
                ) from exc

        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 60))
            logger.warning(
                "VT rate limit hit for %s. Sleeping %ds (attempt %d/%d)",
                url,
                retry_after,
                attempt + 1,
                max_retries + 1,
            )
            time.sleep(retry_after)
            continue

        if resp.status_code == 401:
            raise PermissionError(
                "VirusTotal API key is invalid or expired (HTTP 401)."
            )

        if resp.status_code == 404:
            logger.info("VT returned 404 for %s — indicator not in database", url)
            return {}

        # Unexpected status — surface it
        resp.raise_for_status()

    raise RuntimeError(
        f"VT request to {url} failed after {max_retries + 1} attempts (rate-limited)"
    )


def fetch_ip_report(ip: str, cfg: Config) -> dict[str, Any]:
    """
    Fetch a VirusTotal IP address report.

    Args:
        ip:  IPv4 or IPv6 address string.
        cfg: Application configuration.

    Returns:
        Raw VT API JSON response dict (may be empty if 404).
    """
    url = f"{_VT_BASE}/ip_addresses/{ip}"
    session = _build_session(cfg)
    logger.info("Fetching VT IP report for %s", ip)
    return _get_with_rate_limit(session, url, cfg.request_timeout, cfg.max_retries)


def fetch_file_report(file_hash: str, cfg: Config) -> dict[str, Any]:
    """
    Fetch a VirusTotal file hash report.

    Accepts MD5, SHA-1, or SHA-256 hashes.

    Args:
        file_hash: Hash string.
        cfg:       Application configuration.

    Returns:
        Raw VT API JSON response dict (may be empty if 404).
    """
    url = f"{_VT_BASE}/files/{file_hash}"
    session = _build_session(cfg)
    logger.info("Fetching VT file report for hash %s", file_hash)
    return _get_with_rate_limit(session, url, cfg.request_timeout, cfg.max_retries)
