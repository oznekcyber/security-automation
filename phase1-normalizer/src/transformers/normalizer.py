"""
Alert normalization logic for Security Alert Normalizer.

This module is the beating heart of Phase 1.  It takes the
vendor-specific API responses from VirusTotal and AbuseIPDB and
transforms them into a unified ``NormalizedAlert``.

It also exposes a ``apply_jq_filter`` helper that uses the Python
``jq`` library to let callers slice-and-dice a list of normalized
alert dicts with arbitrary jq expressions — exactly as a SOAR
engineer would do in a real playbook.

Threat score formula
--------------------
VirusTotal (IPs and hashes)
    score = round((malicious + suspicious) / total_engines * 100)
    Capped at 100.  If no engines ran, score is 0.

AbuseIPDB
    score = abuse_confidence_score (already 0-100 per their API docs)

Verdict thresholds (opinionated, matches common SOC SOP)
    >= 70  → malicious
    >= 30  → suspicious
    > 0    → suspicious  (any signal at all)
    == 0   → clean
    unknown when we have no data
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

import jq

from src.utils.logger import get_logger
from src.transformers.schema import (
    AlertSource,
    AnalysisStats,
    GeoInfo,
    IndicatorType,
    NormalizedAlert,
    Verdict,
)

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Verdict helpers
# ---------------------------------------------------------------------------

def _score_to_verdict(score: int) -> Verdict:
    if score >= 70:
        return Verdict.MALICIOUS
    if score >= 30:
        return Verdict.SUSPICIOUS
    if score > 0:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


def _parse_vt_epoch(epoch: Optional[int]) -> Optional[str]:
    """Convert a Unix timestamp (as returned by VT) to ISO-8601 UTC."""
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


# ---------------------------------------------------------------------------
# VirusTotal normalizer
# ---------------------------------------------------------------------------

def normalize_virustotal(
    raw: dict[str, Any],
    indicator_value: str,
    indicator_type: IndicatorType,
) -> NormalizedAlert:
    """
    Transform a raw VirusTotal v3 API response into a NormalizedAlert.

    The VT response structure differs between the ``/ip_addresses/{ip}``
    and ``/files/{hash}`` endpoints but they share the same ``attributes``
    sub-object for the fields we care about.

    Args:
        raw:             The full JSON response dict from VT.
        indicator_value: The IP address or file hash string.
        indicator_type:  ``IndicatorType.IP`` or ``IndicatorType.FILE_HASH``.

    Returns:
        A populated ``NormalizedAlert``.
    """
    collection_ts = datetime.now(timezone.utc).isoformat()
    attrs: dict[str, Any] = raw.get("data", {}).get("attributes", {})

    if not attrs:
        logger.warning(
            "VT response for %s has no 'data.attributes' — returning minimal alert",
            indicator_value,
        )
        return NormalizedAlert(
            indicator_value=indicator_value,
            indicator_type=indicator_type,
            source=AlertSource.VIRUSTOTAL,
            verdict=Verdict.UNKNOWN,
            collection_timestamp=collection_ts,
        )

    # --- Analysis stats ---
    raw_stats: dict[str, int] = attrs.get("last_analysis_stats", {})
    stats = AnalysisStats(
        malicious=raw_stats.get("malicious", 0),
        suspicious=raw_stats.get("suspicious", 0),
        harmless=raw_stats.get("harmless", 0),
        undetected=raw_stats.get("undetected", 0),
        timeout=raw_stats.get("timeout", 0),
    )

    # --- Threat score ---
    total = stats.total_engines
    if total > 0:
        raw_score = round((stats.malicious + stats.suspicious) / total * 100)
        threat_score = min(raw_score, 100)
    else:
        threat_score = 0

    # --- Verdict ---
    # If VT explicitly provides a reputation field we weight it slightly
    reputation: int = attrs.get("reputation", 0)
    if reputation < -20 and threat_score < 30:
        # Strong negative community reputation even if engines didn't flag it
        threat_score = max(threat_score, 30)

    verdict = _score_to_verdict(threat_score)

    # --- Tags ---
    tags: list[str] = []
    # VT tags field (present on file objects)
    vt_tags: list[str] = attrs.get("tags", [])
    tags.extend(vt_tags)
    # Crowdsourced context tags (present on IP objects)
    for ctx in attrs.get("crowdsourced_context", []):
        if isinstance(ctx, dict) and ctx.get("title"):
            tags.append(ctx["title"])

    # --- Categories ---
    # VT returns categories as a dict of vendor → category
    raw_cats = attrs.get("categories", {})
    if isinstance(raw_cats, dict):
        categories = list(set(raw_cats.values()))
    else:
        categories = []

    # --- Geo (IP only) ---
    # VT returns a two-letter ISO country code in the "country" field;
    # there is no separate full-name field at this endpoint level.
    geo: Optional[GeoInfo] = None
    if indicator_type == IndicatorType.IP:
        country_code = attrs.get("country")
        geo = GeoInfo(
            country=None,        # VT doesn't provide the full country name
            country_code=country_code,
            asn=attrs.get("asn"),
            as_owner=attrs.get("as_owner"),
            network=attrs.get("network"),
        )

    # --- Last analysis date ---
    last_analysis_date = _parse_vt_epoch(attrs.get("last_analysis_date"))

    alert = NormalizedAlert(
        indicator_value=indicator_value,
        indicator_type=indicator_type,
        source=AlertSource.VIRUSTOTAL,
        threat_score=threat_score,
        verdict=verdict,
        tags=tags,
        categories=categories,
        geo=geo,
        analysis_stats=stats,
        last_analysis_date=last_analysis_date,
        collection_timestamp=collection_ts,
    )

    logger.info(
        "VT normalized %s %s → score=%d verdict=%s",
        indicator_type.value,
        indicator_value,
        threat_score,
        verdict.value,
    )
    return alert


# ---------------------------------------------------------------------------
# AbuseIPDB normalizer
# ---------------------------------------------------------------------------

def normalize_abuseipdb(
    raw: dict[str, Any],
    indicator_value: str,
) -> NormalizedAlert:
    """
    Transform a raw AbuseIPDB v2 API response into a NormalizedAlert.

    AbuseIPDB only supports IP addresses, so ``indicator_type`` is
    always ``IndicatorType.IP``.

    Args:
        raw:             The full JSON response dict from AbuseIPDB.
        indicator_value: The IP address string.

    Returns:
        A populated ``NormalizedAlert``.
    """
    collection_ts = datetime.now(timezone.utc).isoformat()
    data: dict[str, Any] = raw.get("data", {})

    if not data:
        logger.warning(
            "AbuseIPDB response for %s has no 'data' — returning minimal alert",
            indicator_value,
        )
        return NormalizedAlert(
            indicator_value=indicator_value,
            indicator_type=IndicatorType.IP,
            source=AlertSource.ABUSEIPDB,
            verdict=Verdict.UNKNOWN,
            collection_timestamp=collection_ts,
        )

    abuse_confidence: int = data.get("abuseConfidenceScore", 0)
    total_reports: int = data.get("totalReports", 0)
    # Defensively cap at 100 even though the API documents 0-100 range
    threat_score: int = min(abuse_confidence, 100)
    verdict = _score_to_verdict(threat_score)

    # --- Geo ---
    geo = GeoInfo(
        country=data.get("countryName"),
        country_code=data.get("countryCode"),
        isp=data.get("isp"),
        # AbuseIPDB doesn't return ASN as an integer but domain gives context
    )

    # --- Categories from reports ---
    # AbuseIPDB returns category IDs in report entries if maxAgeInDays was set
    # At the /check endpoint level we only get the summary
    categories: list[str] = []
    usage_type = data.get("usageType")
    if usage_type:
        categories.append(usage_type)

    # --- Tags ---
    tags: list[str] = []
    if data.get("isWhitelisted"):
        tags.append("whitelisted")
    if data.get("isTor"):
        tags.append("tor-exit-node")

    last_report = data.get("lastReportedAt")

    alert = NormalizedAlert(
        indicator_value=indicator_value,
        indicator_type=IndicatorType.IP,
        source=AlertSource.ABUSEIPDB,
        threat_score=threat_score,
        verdict=verdict,
        tags=tags,
        categories=categories,
        geo=geo,
        abuse_confidence_score=abuse_confidence,
        total_abuse_reports=total_reports,
        last_analysis_date=last_report,
        collection_timestamp=collection_ts,
    )

    logger.info(
        "AbuseIPDB normalized IP %s → confidence=%d verdict=%s",
        indicator_value,
        abuse_confidence,
        verdict.value,
    )
    return alert


# ---------------------------------------------------------------------------
# JQ filtering
# ---------------------------------------------------------------------------

def apply_jq_filter(alerts: list[dict], jq_expression: str) -> Any:
    """
    Apply a jq filter expression to a list of normalized alert dicts.

    This lets callers extract precisely the fields they need without
    writing custom Python — exactly how a SOAR engineer would use jq
    in a playbook action.

    Example expressions
    -------------------
    ``'.[] | select(.verdict == "malicious") | {id: .alert_id, ip: .indicator_value}``
        Returns id/ip pairs for every malicious alert.

    ``'[.[] | .threat_score] | add / length'``
        Returns the average threat score across all alerts.

    ``'.[] | select(.source == "abuseipdb") | .geo.country'``
        Returns the country for every AbuseIPDB-sourced alert.

    Args:
        alerts:        List of ``NormalizedAlert.to_dict()`` dicts.
        jq_expression: A valid jq filter string.

    Returns:
        Whatever the jq expression evaluates to (list, dict, scalar…).

    Raises:
        ValueError: If the jq expression is syntactically invalid.
        RuntimeError: If jq evaluation fails for another reason.
    """
    try:
        program = jq.compile(jq_expression)
    except ValueError as exc:
        raise ValueError(f"Invalid jq expression '{jq_expression}': {exc}") from exc

    try:
        result = program.input(alerts).all()
        # jq.all() returns a list; if the expression produces a single scalar
        # we unwrap it for convenience
        if isinstance(result, list) and len(result) == 1:
            return result[0]
        return result
    except Exception as exc:  # jq raises generic Exception on runtime errors
        raise RuntimeError(
            f"jq evaluation failed for expression '{jq_expression}': {exc}"
        ) from exc


def serialize_alerts(alerts: list[NormalizedAlert]) -> str:
    """
    Serialize a list of NormalizedAlert objects to a pretty-printed JSON string.

    Args:
        alerts: List of ``NormalizedAlert`` instances.

    Returns:
        Pretty-printed JSON string.
    """
    return json.dumps([a.to_dict() for a in alerts], indent=2, default=str)
