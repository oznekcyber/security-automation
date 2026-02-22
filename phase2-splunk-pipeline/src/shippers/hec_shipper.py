"""Splunk HTTP Event Collector (HEC) shipper.

Sends structured events to Splunk via the HEC REST endpoint using
``requests``.  Implements:

* Correct ``Authorization: Splunk <token>`` header.
* Exponential back-off retry on HTTP 429 (rate-limit) and 5xx errors.
* Separate shipper logger so every HTTP attempt is auditable independently
  of the application log.
* Custom :class:`HECError` for unrecoverable failures so callers can decide
  whether to skip or halt.
"""

from __future__ import annotations

import json
import socket
import time
from typing import Any, Dict, List, Optional

import requests
import urllib3

from src.utils.config import Config
from src.utils.logger import SHIPPER_LOGGER_NAME, get_logger

import logging

# Silence the noisy urllib3 InsecureRequestWarning that fires when
# verify=False is used against self-signed Splunk dev instances.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_shipper_log = logging.getLogger(SHIPPER_LOGGER_NAME)
_app_log = get_logger("hec_shipper")


class HECError(Exception):
    """Raised when an event cannot be delivered to the Splunk HEC endpoint
    after all retry attempts have been exhausted."""


class HECShipper:
    """Production-quality Splunk HEC event shipper.

    Parameters
    ----------
    config:
        Populated :class:`~src.utils.config.Config` instance.
    dry_run:
        When *True* the shipper logs what it *would* send but makes no
        actual HTTP requests.  Useful for local testing without a live
        Splunk instance.
    """

    _HEC_PATH = "/services/collector/event"

    def __init__(self, config: Config, dry_run: bool = False) -> None:
        self._config = config
        self._dry_run = dry_run
        self._url = config.splunk_url.rstrip("/") + self._HEC_PATH
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Splunk {config.hec_token}",
                "Content-Type": "application/json",
            }
        )
        self._hostname = socket.gethostname()

    # ── public API ────────────────────────────────────────────────────────────

    def send_event(
        self,
        event_dict: Dict[str, Any],
        sourcetype: str,
        index: Optional[str] = None,
    ) -> None:
        """Send a single event to Splunk HEC.

        Parameters
        ----------
        event_dict:
            The raw event payload (will be nested under ``event`` key).
        sourcetype:
            Splunk sourcetype string (e.g. ``syslog:ssh``).
        index:
            Splunk index override.  Falls back to ``config.index_name``.

        Raises
        ------
        HECError
            If the event could not be delivered after all retries.
        """
        payload = self._build_hec_payload(event_dict, sourcetype, index)
        self._send_with_retry(json.dumps(payload))

    def send_batch(
        self,
        events: List[Dict[str, Any]],
        sourcetype: str,
        index: Optional[str] = None,
    ) -> None:
        """Send a batch of events using HEC's newline-delimited format.

        All events in *events* share the same *sourcetype* and *index*.

        Parameters
        ----------
        events:
            List of raw event dicts.
        sourcetype:
            Splunk sourcetype.
        index:
            Splunk index override.

        Raises
        ------
        HECError
            If the batch could not be delivered after all retries.
        """
        if not events:
            return
        lines = "\n".join(
            json.dumps(self._build_hec_payload(ev, sourcetype, index))
            for ev in events
        )
        _app_log.info("Sending batch of %d events (sourcetype=%s)", len(events), sourcetype)
        self._send_with_retry(lines)

    # ── internal helpers ──────────────────────────────────────────────────────

    def _build_hec_payload(
        self,
        event_dict: Dict[str, Any],
        sourcetype: str,
        index: Optional[str],
    ) -> Dict[str, Any]:
        """Build a fully-formed HEC JSON payload dict.

        Parameters
        ----------
        event_dict:
            Raw event data.
        sourcetype:
            Splunk sourcetype string.
        index:
            Target index; defaults to ``config.index_name``.

        Returns
        -------
        Dict[str, Any]
            HEC envelope ready for ``json.dumps``.
        """
        # Use epoch time from event if available, otherwise current time.
        ts_str: Optional[str] = event_dict.get("timestamp")
        try:
            from datetime import datetime, timezone  # local import to avoid top-level dep cycle
            epoch = (
                datetime.fromisoformat(ts_str).timestamp()
                if ts_str
                else time.time()
            )
        except (ValueError, TypeError):
            epoch = time.time()

        return {
            "time": epoch,
            "host": event_dict.get("source_host") or event_dict.get("hostname") or self._hostname,
            "source": event_dict.get("event_type", "python-pipeline"),
            "sourcetype": sourcetype,
            "index": index or self._config.index_name,
            "event": event_dict,
        }

    def _send_with_retry(self, body: str) -> None:
        """POST *body* to the HEC endpoint with exponential back-off.

        Parameters
        ----------
        body:
            JSON string (single event or newline-delimited batch).

        Raises
        ------
        HECError
            After :attr:`config.max_retries` consecutive failures.
        """
        if self._dry_run:
            _shipper_log.info("[DRY-RUN] Would POST %d bytes to %s", len(body), self._url)
            return

        last_exc: Optional[Exception] = None
        for attempt in range(1, self._config.max_retries + 1):
            try:
                resp = self._session.post(
                    self._url,
                    data=body,
                    timeout=10,
                    verify=False,  # allow self-signed certs in dev
                )
                _shipper_log.debug(
                    "POST %s → HTTP %d (attempt %d/%d)",
                    self._url,
                    resp.status_code,
                    attempt,
                    self._config.max_retries,
                )
                if resp.status_code == 200:
                    return
                if resp.status_code in (429, 500, 502, 503, 504):
                    # Transient – retry after back-off.
                    wait = self._config.retry_backoff_factor ** attempt
                    _shipper_log.warning(
                        "Transient HTTP %d; retrying in %.1f s (attempt %d/%d)",
                        resp.status_code,
                        wait,
                        attempt,
                        self._config.max_retries,
                    )
                    time.sleep(wait)
                    last_exc = HECError(f"HTTP {resp.status_code}: {resp.text[:200]}")
                    continue
                # Non-retryable error (e.g. 400 Bad Request, 403 Forbidden).
                raise HECError(
                    f"Non-retryable HTTP {resp.status_code} from HEC: {resp.text[:200]}"
                )
            except requests.exceptions.RequestException as exc:
                wait = self._config.retry_backoff_factor ** attempt
                _shipper_log.warning(
                    "Network error on attempt %d/%d: %s; retrying in %.1f s",
                    attempt,
                    self._config.max_retries,
                    exc,
                    wait,
                )
                time.sleep(wait)
                last_exc = exc

        raise HECError(
            f"HEC delivery failed after {self._config.max_retries} attempts"
        ) from last_exc
