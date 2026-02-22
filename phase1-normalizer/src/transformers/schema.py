"""
Unified alert schema for Security Alert Normalizer.

This module defines the canonical NormalizedAlert structure that every
collector must produce.  Downstream tools (SIEM ingest, SOAR playbooks,
dashboards) consume only this schema — they never touch vendor-specific
API responses.

Design philosophy
-----------------
*  Flat where it matters, nested where grouping aids readability.
*  Every field that may be absent is Optional with a sane default.
*  ``threat_score`` is always 0-100 regardless of source so that
   downstream triage logic doesn't need to know who generated the alert.
*  ``verdict`` is an explicit enum so playbooks can do simple
   equality checks instead of re-implementing scoring thresholds.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class IndicatorType(str, Enum):
    IP = "ip"
    FILE_HASH = "file_hash"


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class AlertSource(str, Enum):
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"


@dataclass
class GeoInfo:
    """Geographic and network context for IP indicators."""

    country: Optional[str] = None
    country_code: Optional[str] = None
    asn: Optional[int] = None
    as_owner: Optional[str] = None
    isp: Optional[str] = None
    network: Optional[str] = None


@dataclass
class AnalysisStats:
    """
    Community analysis vote counts.

    Present for VirusTotal alerts; zeroed-out for AbuseIPDB alerts
    where equivalent data is not returned.
    """

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    timeout: int = 0

    @property
    def total_engines(self) -> int:
        return (
            self.malicious
            + self.suspicious
            + self.harmless
            + self.undetected
            + self.timeout
        )

    @property
    def detection_rate(self) -> float:
        """Fraction of engines that flagged the indicator as malicious."""
        total = self.total_engines
        if total == 0:
            return 0.0
        return round((self.malicious + self.suspicious) / total, 4)


@dataclass
class NormalizedAlert:
    """
    The canonical alert record produced by every normalizer.

    Fields
    ------
    alert_id        : Globally unique identifier (UUID4) assigned at
                      normalization time.
    timestamp       : ISO-8601 UTC timestamp when the alert was
                      normalized (not when the threat was first seen).
    source          : Which API produced this alert.
    indicator_type  : ``ip`` or ``file_hash``.
    indicator_value : The raw indicator (IP address or hash string).
    threat_score    : 0-100 composite risk score.
    verdict         : High-level triage classification.
    tags            : Free-form labels (e.g. ``["ransomware", "c2"]``).
    geo             : Geographic context — populated only for IPs.
    analysis_stats  : Engine vote counts from VirusTotal.
    abuse_confidence_score : AbuseIPDB's own 0-100 abuse confidence.
    total_abuse_reports    : Number of distinct reports on AbuseIPDB.
    last_analysis_date     : When the vendor last analysed this indicator.
    collection_timestamp   : When our collector fetched the data (UTC ISO-8601).
    categories      : Vendor-supplied category labels.
    """

    indicator_value: str
    indicator_type: IndicatorType
    source: AlertSource

    # Set automatically if not provided
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    threat_score: int = 0
    verdict: Verdict = Verdict.UNKNOWN

    tags: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)

    geo: Optional[GeoInfo] = None
    analysis_stats: Optional[AnalysisStats] = None

    abuse_confidence_score: int = 0
    total_abuse_reports: int = 0

    last_analysis_date: Optional[str] = None
    collection_timestamp: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialize to a plain dictionary suitable for JSON encoding."""
        d = asdict(self)
        # Convert enums to their string values
        d["source"] = self.source.value
        d["indicator_type"] = self.indicator_type.value
        d["verdict"] = self.verdict.value
        return d
