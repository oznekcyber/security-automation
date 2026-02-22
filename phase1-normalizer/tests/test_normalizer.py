"""
Unit tests for the normalization and transformation logic.

These tests run entirely offline — no API keys or network access
required.  Mock API responses mirror the real structure returned by
the VirusTotal v3 and AbuseIPDB v2 APIs.

Run with:
    pytest tests/ -v
"""

from __future__ import annotations

import json
import pytest

from src.transformers.schema import (
    AlertSource,
    AnalysisStats,
    IndicatorType,
    NormalizedAlert,
    Verdict,
)
from src.transformers.normalizer import (
    normalize_virustotal,
    normalize_abuseipdb,
    apply_jq_filter,
    serialize_alerts,
)


# ---------------------------------------------------------------------------
# Fixtures — realistic mock API responses
# ---------------------------------------------------------------------------

@pytest.fixture
def vt_ip_malicious() -> dict:
    """Typical VT response for a known-malicious Tor exit node."""
    return {
        "data": {
            "id": "185.220.101.1",
            "type": "ip_address",
            "attributes": {
                "country": "DE",
                "asn": 205100,
                "as_owner": "F3 Netze e.V.",
                "network": "185.220.101.0/24",
                "reputation": -81,
                "last_analysis_date": 1708300800,
                "last_analysis_stats": {
                    "malicious": 65,
                    "suspicious": 5,
                    "harmless": 10,
                    "undetected": 12,
                    "timeout": 0,
                },
                "tags": ["tor", "proxy"],
                "categories": {
                    "Forcepoint ThreatSeeker": "proxy avoidance and anonymizers",
                    "Sophos": "tor",
                },
            },
        }
    }


@pytest.fixture
def vt_ip_clean() -> dict:
    """VT response for a reputable IP (Google DNS)."""
    return {
        "data": {
            "id": "8.8.8.8",
            "type": "ip_address",
            "attributes": {
                "country": "US",
                "asn": 15169,
                "as_owner": "Google LLC",
                "network": "8.8.8.0/24",
                "reputation": 100,
                "last_analysis_date": 1708300800,
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 90,
                    "undetected": 2,
                    "timeout": 0,
                },
                "tags": [],
                "categories": {},
            },
        }
    }


@pytest.fixture
def vt_hash_malicious() -> dict:
    """VT response for the EICAR test file (detected by almost every AV)."""
    return {
        "data": {
            "id": "44d88612fea8a8f36de82e1278abb02f",
            "type": "file",
            "attributes": {
                "meaningful_name": "eicar.com",
                "last_analysis_date": 1708214400,
                "last_analysis_stats": {
                    "malicious": 67,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 5,
                    "timeout": 0,
                },
                "tags": ["eicar", "test-file"],
                "categories": {
                    "Bkav": "W32.AIDetect.malware1",
                    "MicroWorld-eScan": "EICAR-Test-File",
                },
            },
        }
    }


@pytest.fixture
def abuse_ip_malicious() -> dict:
    """AbuseIPDB response for a heavily abused Tor exit node."""
    return {
        "data": {
            "ipAddress": "185.220.101.1",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidenceScore": 100,
            "countryCode": "DE",
            "countryName": "Germany",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "F3 Netze e.V.",
            "domain": "f3netze.de",
            "isTor": True,
            "totalReports": 1847,
            "numDistinctUsers": 312,
            "lastReportedAt": "2024-02-18T12:00:00+00:00",
        }
    }


@pytest.fixture
def abuse_ip_clean() -> dict:
    """AbuseIPDB response for a clean IP with zero reports."""
    return {
        "data": {
            "ipAddress": "8.8.8.8",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": True,
            "abuseConfidenceScore": 0,
            "countryCode": "US",
            "countryName": "United States",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Google LLC",
            "domain": "google.com",
            "isTor": False,
            "totalReports": 0,
            "numDistinctUsers": 0,
            "lastReportedAt": None,
        }
    }


# ---------------------------------------------------------------------------
# NormalizedAlert schema tests
# ---------------------------------------------------------------------------

class TestNormalizedAlertSchema:
    def test_default_verdict_is_unknown(self):
        alert = NormalizedAlert(
            indicator_value="1.2.3.4",
            indicator_type=IndicatorType.IP,
            source=AlertSource.VIRUSTOTAL,
        )
        assert alert.verdict == Verdict.UNKNOWN

    def test_auto_generated_alert_id_is_uuid(self):
        alert = NormalizedAlert(
            indicator_value="1.2.3.4",
            indicator_type=IndicatorType.IP,
            source=AlertSource.VIRUSTOTAL,
        )
        import uuid
        uuid.UUID(alert.alert_id)  # raises if not a valid UUID

    def test_to_dict_produces_string_enums(self):
        alert = NormalizedAlert(
            indicator_value="1.2.3.4",
            indicator_type=IndicatorType.IP,
            source=AlertSource.VIRUSTOTAL,
            verdict=Verdict.MALICIOUS,
        )
        d = alert.to_dict()
        assert d["source"] == "virustotal"
        assert d["indicator_type"] == "ip"
        assert d["verdict"] == "malicious"

    def test_analysis_stats_total_and_detection_rate(self):
        stats = AnalysisStats(malicious=18, suspicious=2, harmless=60, undetected=12)
        assert stats.total_engines == 92
        assert stats.detection_rate == round(20 / 92, 4)

    def test_analysis_stats_zero_total(self):
        stats = AnalysisStats()
        assert stats.total_engines == 0
        assert stats.detection_rate == 0.0


# ---------------------------------------------------------------------------
# VirusTotal normalizer tests
# ---------------------------------------------------------------------------

class TestNormalizeVirusTotal:
    def test_malicious_ip_verdict(self, vt_ip_malicious):
        alert = normalize_virustotal(vt_ip_malicious, "185.220.101.1", IndicatorType.IP)
        assert alert.verdict == Verdict.MALICIOUS
        assert alert.threat_score > 0

    def test_malicious_ip_has_correct_source(self, vt_ip_malicious):
        alert = normalize_virustotal(vt_ip_malicious, "185.220.101.1", IndicatorType.IP)
        assert alert.source == AlertSource.VIRUSTOTAL

    def test_malicious_ip_geo_populated(self, vt_ip_malicious):
        alert = normalize_virustotal(vt_ip_malicious, "185.220.101.1", IndicatorType.IP)
        assert alert.geo is not None
        assert alert.geo.country_code == "DE"
        assert alert.geo.asn == 205100

    def test_malicious_ip_tags(self, vt_ip_malicious):
        alert = normalize_virustotal(vt_ip_malicious, "185.220.101.1", IndicatorType.IP)
        assert "tor" in alert.tags
        assert "proxy" in alert.tags

    def test_malicious_ip_categories(self, vt_ip_malicious):
        alert = normalize_virustotal(vt_ip_malicious, "185.220.101.1", IndicatorType.IP)
        assert len(alert.categories) > 0

    def test_clean_ip_verdict(self, vt_ip_clean):
        alert = normalize_virustotal(vt_ip_clean, "8.8.8.8", IndicatorType.IP)
        assert alert.verdict == Verdict.CLEAN
        assert alert.threat_score == 0

    def test_malicious_hash_verdict(self, vt_hash_malicious):
        alert = normalize_virustotal(
            vt_hash_malicious,
            "44d88612fea8a8f36de82e1278abb02f",
            IndicatorType.FILE_HASH,
        )
        assert alert.verdict == Verdict.MALICIOUS
        assert alert.threat_score == 93  # 67/72 ≈ 93%

    def test_hash_has_no_geo(self, vt_hash_malicious):
        alert = normalize_virustotal(
            vt_hash_malicious,
            "44d88612fea8a8f36de82e1278abb02f",
            IndicatorType.FILE_HASH,
        )
        assert alert.geo is None

    def test_indicator_type_file_hash(self, vt_hash_malicious):
        alert = normalize_virustotal(
            vt_hash_malicious,
            "44d88612fea8a8f36de82e1278abb02f",
            IndicatorType.FILE_HASH,
        )
        assert alert.indicator_type == IndicatorType.FILE_HASH
        assert alert.indicator_value == "44d88612fea8a8f36de82e1278abb02f"

    def test_empty_response_returns_unknown(self):
        alert = normalize_virustotal({}, "1.2.3.4", IndicatorType.IP)
        assert alert.verdict == Verdict.UNKNOWN
        assert alert.threat_score == 0

    def test_missing_last_analysis_stats(self):
        raw = {"data": {"attributes": {"reputation": 0}}}
        alert = normalize_virustotal(raw, "1.2.3.4", IndicatorType.IP)
        assert alert.analysis_stats is not None
        assert alert.analysis_stats.malicious == 0

    def test_threat_score_capped_at_100(self):
        """Edge case: ensure we never produce a score > 100."""
        raw = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 200,
                        "suspicious": 50,
                        "harmless": 0,
                        "undetected": 0,
                        "timeout": 0,
                    }
                }
            }
        }
        alert = normalize_virustotal(raw, "1.2.3.4", IndicatorType.IP)
        assert alert.threat_score <= 100

    def test_last_analysis_date_parsed(self, vt_ip_malicious):
        alert = normalize_virustotal(vt_ip_malicious, "185.220.101.1", IndicatorType.IP)
        assert alert.last_analysis_date is not None
        assert "2024" in alert.last_analysis_date


# ---------------------------------------------------------------------------
# AbuseIPDB normalizer tests
# ---------------------------------------------------------------------------

class TestNormalizeAbuseIPDB:
    def test_malicious_ip_verdict(self, abuse_ip_malicious):
        alert = normalize_abuseipdb(abuse_ip_malicious, "185.220.101.1")
        assert alert.verdict == Verdict.MALICIOUS

    def test_malicious_ip_confidence_score(self, abuse_ip_malicious):
        alert = normalize_abuseipdb(abuse_ip_malicious, "185.220.101.1")
        assert alert.abuse_confidence_score == 100
        assert alert.total_abuse_reports == 1847

    def test_malicious_ip_geo(self, abuse_ip_malicious):
        alert = normalize_abuseipdb(abuse_ip_malicious, "185.220.101.1")
        assert alert.geo is not None
        assert alert.geo.country_code == "DE"
        assert alert.geo.isp == "F3 Netze e.V."

    def test_tor_tag_added(self, abuse_ip_malicious):
        alert = normalize_abuseipdb(abuse_ip_malicious, "185.220.101.1")
        assert "tor-exit-node" in alert.tags

    def test_whitelisted_tag_added(self, abuse_ip_clean):
        alert = normalize_abuseipdb(abuse_ip_clean, "8.8.8.8")
        assert "whitelisted" in alert.tags

    def test_clean_ip_verdict(self, abuse_ip_clean):
        alert = normalize_abuseipdb(abuse_ip_clean, "8.8.8.8")
        assert alert.verdict == Verdict.CLEAN
        assert alert.threat_score == 0

    def test_always_ip_indicator_type(self, abuse_ip_malicious):
        alert = normalize_abuseipdb(abuse_ip_malicious, "185.220.101.1")
        assert alert.indicator_type == IndicatorType.IP

    def test_source_is_abuseipdb(self, abuse_ip_malicious):
        alert = normalize_abuseipdb(abuse_ip_malicious, "185.220.101.1")
        assert alert.source == AlertSource.ABUSEIPDB

    def test_empty_response_returns_unknown(self):
        alert = normalize_abuseipdb({}, "1.2.3.4")
        assert alert.verdict == Verdict.UNKNOWN

    def test_usage_type_in_categories(self, abuse_ip_malicious):
        alert = normalize_abuseipdb(abuse_ip_malicious, "185.220.101.1")
        assert "Data Center/Web Hosting/Transit" in alert.categories


# ---------------------------------------------------------------------------
# Serialization tests
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_to_dict_is_json_serializable(self, vt_ip_malicious):
        alert = normalize_virustotal(vt_ip_malicious, "185.220.101.1", IndicatorType.IP)
        d = alert.to_dict()
        # Should not raise
        json_str = json.dumps(d)
        assert "185.220.101.1" in json_str

    def test_serialize_alerts_produces_list(self, vt_ip_malicious, abuse_ip_malicious):
        alerts = [
            normalize_virustotal(vt_ip_malicious, "185.220.101.1", IndicatorType.IP),
            normalize_abuseipdb(abuse_ip_malicious, "185.220.101.1"),
        ]
        result = json.loads(serialize_alerts(alerts))
        assert isinstance(result, list)
        assert len(result) == 2

    def test_serialize_preserves_verdict_string(self, vt_ip_malicious):
        alert = normalize_virustotal(vt_ip_malicious, "185.220.101.1", IndicatorType.IP)
        result = json.loads(serialize_alerts([alert]))
        assert result[0]["verdict"] == "malicious"


# ---------------------------------------------------------------------------
# JQ filtering tests
# ---------------------------------------------------------------------------

class TestJQFilter:
    def _make_alerts(self, vt_ip_malicious, abuse_ip_clean):
        return [
            normalize_virustotal(vt_ip_malicious, "185.220.101.1", IndicatorType.IP).to_dict(),
            normalize_abuseipdb(abuse_ip_clean, "8.8.8.8").to_dict(),
        ]

    def test_filter_malicious_only(self, vt_ip_malicious, abuse_ip_clean):
        alerts = self._make_alerts(vt_ip_malicious, abuse_ip_clean)
        result = apply_jq_filter(alerts, '[.[] | select(.verdict == "malicious")]')
        assert isinstance(result, list)
        assert all(a["verdict"] == "malicious" for a in result)

    def test_filter_by_source(self, vt_ip_malicious, abuse_ip_clean):
        alerts = self._make_alerts(vt_ip_malicious, abuse_ip_clean)
        result = apply_jq_filter(alerts, '[.[] | select(.source == "abuseipdb")]')
        assert all(a["source"] == "abuseipdb" for a in result)

    def test_extract_indicator_values(self, vt_ip_malicious, abuse_ip_clean):
        alerts = self._make_alerts(vt_ip_malicious, abuse_ip_clean)
        result = apply_jq_filter(alerts, "[.[].indicator_value]")
        assert isinstance(result, list)
        assert "185.220.101.1" in result

    def test_invalid_expression_raises_value_error(self, vt_ip_malicious, abuse_ip_clean):
        alerts = self._make_alerts(vt_ip_malicious, abuse_ip_clean)
        with pytest.raises(ValueError):
            apply_jq_filter(alerts, "this is not valid jq!!!@#$%")

    def test_count_alerts(self, vt_ip_malicious, abuse_ip_clean):
        alerts = self._make_alerts(vt_ip_malicious, abuse_ip_clean)
        result = apply_jq_filter(alerts, "length")
        assert result == 2

    def test_select_geo_country(self, vt_ip_malicious, abuse_ip_clean):
        alerts = self._make_alerts(vt_ip_malicious, abuse_ip_clean)
        result = apply_jq_filter(
            alerts,
            '[.[] | select(.source == "virustotal") | .geo.country_code]',
        )
        assert "DE" in result
