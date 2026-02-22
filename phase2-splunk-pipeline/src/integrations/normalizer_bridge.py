"""Phase 1 → Phase 2 integration bridge.

Accepts plain Python dicts that conform to the Phase 1 ``NormalizedAlert``
schema (produced by the threat-intel normalizer) and transforms them into
Splunk-ready events ingested via :class:`~src.shippers.hec_shipper.HECShipper`.

No direct import of Phase 1 code is required – the bridge works entirely with
plain dicts so the two phases can be deployed independently.

Phase 1 NormalizedAlert schema (expected keys)
-----------------------------------------------
alert_id            – UUID string
timestamp           – ISO-8601 UTC
source              – "virustotal" | "abuseipdb"
indicator_type      – "ip" | "file_hash"
indicator_value     – raw IP or hash string
threat_score        – 0-100 int
verdict             – "malicious" | "suspicious" | "clean" | "unknown"
tags                – list[str]
categories          – list[str]
geo                 – dict (country, country_code, asn, as_owner, isp, network)
analysis_stats      – dict (malicious, suspicious, harmless, undetected, timeout)
abuse_confidence_score  – 0-100 int
total_abuse_reports – int
last_analysis_date  – ISO-8601 (optional)
collection_timestamp – ISO-8601 (optional)
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from src.shippers.hec_shipper import HECShipper
from src.utils.config import Config
from src.utils.logger import get_logger

_log = get_logger("normalizer_bridge")

# Sourcetype used for all Phase 1 normalizer events in Splunk.
NORMALIZER_SOURCETYPE = "threat:normalizer"


class NormalizerBridge:
    """Transform and ingest Phase 1 NormalizedAlert dicts into Splunk.

    Parameters
    ----------
    shipper:
        Initialised :class:`~src.shippers.hec_shipper.HECShipper`.
    config:
        Pipeline configuration (used for ``normalizer_index``).
    """

    def __init__(self, shipper: HECShipper, config: Config) -> None:
        self._shipper = shipper
        self._config = config

    # ── public API ────────────────────────────────────────────────────────────

    def ingest_alert(self, alert_dict: Dict[str, Any]) -> None:
        """Transform one NormalizedAlert dict and ship it to Splunk.

        Parameters
        ----------
        alert_dict:
            Plain dict matching the Phase 1 NormalizedAlert schema.
        """
        enriched = self._transform(alert_dict)
        self._shipper.send_event(
            enriched,
            sourcetype=NORMALIZER_SOURCETYPE,
            index=self._config.normalizer_index,
        )
        _log.info(
            "Ingested alert %s (verdict=%s, score=%s)",
            alert_dict.get("alert_id", "?"),
            alert_dict.get("verdict", "?"),
            alert_dict.get("threat_score", "?"),
        )

    def ingest_alerts_file(self, filepath: str) -> int:
        """Read a JSON file of NormalizedAlert dicts and ingest each one.

        The file may contain either a JSON array of alert dicts **or** one
        JSON object per line (newline-delimited JSON / NDJSON).

        Parameters
        ----------
        filepath:
            Absolute or relative path to the JSON file.

        Returns
        -------
        int
            Number of alerts successfully ingested.

        Raises
        ------
        FileNotFoundError
            When *filepath* does not exist.
        ValueError
            When the file cannot be parsed as JSON.
        """
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Normalizer output file not found: {filepath}")

        with open(filepath, encoding="utf-8") as fh:
            content = fh.read().strip()

        alerts: List[Dict[str, Any]]
        # Try JSON array first, then fall back to NDJSON.
        if content.startswith("["):
            alerts = json.loads(content)
        else:
            alerts = [json.loads(line) for line in content.splitlines() if line.strip()]

        return self.ingest_alerts_list(alerts)

    def ingest_alerts_list(self, alerts: List[Dict[str, Any]]) -> int:
        """Ingest a list of NormalizedAlert dicts.

        Parameters
        ----------
        alerts:
            List of plain alert dicts.

        Returns
        -------
        int
            Number of alerts successfully ingested.
        """
        success = 0
        for alert in alerts:
            try:
                self.ingest_alert(alert)
                success += 1
            except Exception as exc:  # noqa: BLE001
                _log.error(
                    "Failed to ingest alert %s: %s",
                    alert.get("alert_id", "?"),
                    exc,
                )
        _log.info("Ingested %d/%d alerts from list", success, len(alerts))
        return success

    # ── transformation logic ──────────────────────────────────────────────────

    def _transform(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a raw NormalizedAlert dict with computed Splunk fields.

        Parameters
        ----------
        alert:
            Raw Phase 1 alert dict.

        Returns
        -------
        Dict[str, Any]
            Enriched dict ready for HEC ingestion.
        """
        verdict: str = alert.get("verdict", "unknown")
        threat_score: int = int(alert.get("threat_score", 0))

        enriched: Dict[str, Any] = {**alert}  # shallow copy, keep all original fields

        # ── severity mapping ──────────────────────────────────────────────────
        enriched["severity"] = _verdict_to_severity(verdict, threat_score)

        # ── computed boolean flags ────────────────────────────────────────────
        enriched["is_malicious"] = verdict == "malicious"
        enriched["is_suspicious"] = verdict == "suspicious"

        # ── geo flattening ────────────────────────────────────────────────────
        geo: Dict[str, Any] = alert.get("geo") or {}
        enriched["geo_country"] = geo.get("country")
        enriched["geo_country_code"] = geo.get("country_code")
        enriched["geo_asn"] = geo.get("asn")
        enriched["geo_as_owner"] = geo.get("as_owner")
        enriched["geo_isp"] = geo.get("isp")

        # ── indicator family ──────────────────────────────────────────────────
        enriched["indicator_family"] = _indicator_family(
            alert.get("indicator_type", ""),
            alert.get("categories", []),
            alert.get("tags", []),
        )

        # ── risk bucket for dashboard colouring ──────────────────────────────
        enriched["risk_bucket"] = _risk_bucket(threat_score)

        # ── pipeline metadata ─────────────────────────────────────────────────
        enriched["pipeline_stage"] = "phase2_splunk"

        return enriched


# ── module-level helper functions ─────────────────────────────────────────────

def _verdict_to_severity(verdict: str, threat_score: int) -> str:
    """Map Phase 1 verdict + score to a Splunk-friendly severity label."""
    if verdict == "malicious":
        return "critical" if threat_score >= 75 else "high"
    if verdict == "suspicious":
        return "medium"
    if verdict == "clean":
        return "low"
    return "informational"


def _indicator_family(
    indicator_type: str,
    categories: List[str],
    tags: List[str],
) -> str:
    """Derive a coarse threat family from indicator metadata."""
    all_labels = {s.lower() for s in (categories + tags)}
    if "ransomware" in all_labels:
        return "ransomware"
    if any(k in all_labels for k in ("rat", "trojan", "backdoor")):
        return "trojan"
    if any(k in all_labels for k in ("miner", "cryptominer")):
        return "cryptominer"
    if "phishing" in all_labels:
        return "phishing"
    if indicator_type == "ip":
        return "malicious_ip"
    if indicator_type == "file_hash":
        return "malware"
    return "unknown"


def _risk_bucket(score: int) -> str:
    """Bucket a 0-100 threat score into a labelled risk tier."""
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"
