"""
Tests for TheHiveCaseBuilder and SlackFormatter — runs entirely offline.

Run with:
    pytest tests/ -v
"""

from __future__ import annotations

import pytest

from src.thehive_case_builder import TheHiveCaseBuilder
from src.slack_formatter import SlackFormatter


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def builder() -> TheHiveCaseBuilder:
    return TheHiveCaseBuilder()


@pytest.fixture
def formatter() -> SlackFormatter:
    return SlackFormatter()


@pytest.fixture
def sample_iocs() -> dict:
    return {
        "ips": ["185.220.101.42"],
        "urls": ["http://evil-domain.ru/payload.exe"],
        "domains": ["evil-domain.ru"],
        "hashes": [{"value": "44d88612fea8a8f36de82e1278abb02f", "type": "md5"}],
        "emails": ["attacker@evil-domain.ru"],
    }


def _score_result(score: float) -> dict:
    """Build a minimal score_result dict for a given score value."""
    if score > 7:
        tier, decision = "CRITICAL", "auto-escalate"
    elif score > 5:
        tier, decision = "HIGH", "auto-escalate"
    elif score > 3:
        tier, decision = "MEDIUM", "analyst-review"
    elif score > 1:
        tier, decision = "LOW", "analyst-review"
    else:
        tier, decision = "INFO", "auto-close"
    return {
        "score": score,
        "tier": tier,
        "decision": decision,
        "breakdown": {
            "vt_detections": {"raw_score": 5.0, "weight": 0.4, "contribution": 2.0, "reasoning": "test"},
        },
        "partial": False,
    }


# ---------------------------------------------------------------------------
# TheHiveCaseBuilder — severity mapping
# ---------------------------------------------------------------------------

class TestTheHiveSeverityMapping:
    def test_critical_score_maps_to_severity_4(self, builder, sample_iocs):
        payload = builder.build("phishing", "Test", sample_iocs, _score_result(8.5))
        assert payload["severity"] == 4

    def test_high_score_maps_to_severity_3(self, builder, sample_iocs):
        payload = builder.build("phishing", "Test", sample_iocs, _score_result(6.0))
        assert payload["severity"] == 3

    def test_medium_score_maps_to_severity_2(self, builder, sample_iocs):
        payload = builder.build("phishing", "Test", sample_iocs, _score_result(4.0))
        assert payload["severity"] == 2

    def test_low_score_maps_to_severity_1(self, builder, sample_iocs):
        payload = builder.build("phishing", "Test", sample_iocs, _score_result(2.0))
        assert payload["severity"] == 1

    def test_boundary_score_5_is_high(self, builder, sample_iocs):
        payload = builder.build("malware", "Test", sample_iocs, _score_result(5.5))
        assert payload["severity"] == 3

    def test_boundary_score_7_is_high(self, builder, sample_iocs):
        # score=7.0 is NOT above 7, so should be HIGH (3)
        payload = builder.build("malware", "Test", sample_iocs, _score_result(7.0))
        assert payload["severity"] == 3

    def test_boundary_score_above_7_is_critical(self, builder, sample_iocs):
        payload = builder.build("malware", "Test", sample_iocs, _score_result(7.1))
        assert payload["severity"] == 4


# ---------------------------------------------------------------------------
# TheHiveCaseBuilder — payload structure
# ---------------------------------------------------------------------------

class TestTheHiveCasePayloadStructure:
    def test_required_fields_present(self, builder, sample_iocs):
        payload = builder.build("phishing", "Alert title", sample_iocs, _score_result(8.0))
        for field in ("title", "description", "severity", "tlp", "pap", "status",
                      "flag", "tags", "tasks", "observables", "customFields"):
            assert field in payload, f"Missing field: {field}"

    def test_status_is_new(self, builder, sample_iocs):
        payload = builder.build("phishing", "Test", sample_iocs, _score_result(3.0))
        assert payload["status"] == "New"

    def test_observables_include_ip(self, builder, sample_iocs):
        payload = builder.build("phishing", "Test", sample_iocs, _score_result(5.0))
        obs_types = {o["dataType"] for o in payload["observables"]}
        assert "ip" in obs_types

    def test_observables_include_hash(self, builder, sample_iocs):
        payload = builder.build("phishing", "Test", sample_iocs, _score_result(5.0))
        obs_types = {o["dataType"] for o in payload["observables"]}
        assert "hash" in obs_types

    def test_tasks_present_for_phishing(self, builder, sample_iocs):
        payload = builder.build("phishing", "Test", sample_iocs, _score_result(6.0))
        assert len(payload["tasks"]) > 0

    def test_tasks_present_for_malware(self, builder, sample_iocs):
        payload = builder.build("malware", "Test", sample_iocs, _score_result(6.0))
        assert len(payload["tasks"]) > 0

    def test_tasks_present_for_network_anomaly(self, builder, sample_iocs):
        payload = builder.build("network_anomaly", "Test", sample_iocs, _score_result(4.0))
        assert len(payload["tasks"]) > 0

    def test_flag_true_for_high_severity(self, builder, sample_iocs):
        payload = builder.build("phishing", "Test", sample_iocs, _score_result(8.0))
        assert payload["flag"] is True

    def test_flag_false_for_low_severity(self, builder, sample_iocs):
        payload = builder.build("phishing", "Test", sample_iocs, _score_result(1.0))
        assert payload["flag"] is False

    def test_description_contains_markdown(self, builder, sample_iocs):
        payload = builder.build("phishing", "Test Alert", sample_iocs, _score_result(7.5))
        desc = payload["description"]
        assert "##" in desc or "#" in desc  # has markdown headers
        assert "185.220.101.42" in desc  # IOCs reflected in description

    def test_custom_fields_populated(self, builder, sample_iocs):
        payload = builder.build("phishing", "Test", sample_iocs, _score_result(6.5))
        cf = payload["customFields"]
        assert cf["riskTier"]["string"] == "HIGH"
        assert cf["soarDecision"]["string"] == "auto-escalate"

    def test_empty_iocs_handled(self, builder):
        empty_iocs = {"ips": [], "urls": [], "domains": [], "hashes": [], "emails": []}
        payload = builder.build("phishing", "Test", empty_iocs, _score_result(3.0))
        assert payload["observables"] == []


# ---------------------------------------------------------------------------
# SlackFormatter — structure tests
# ---------------------------------------------------------------------------

class TestSlackFormatterStructure:
    def test_returns_dict_with_attachments(self, formatter, sample_iocs):
        msg = formatter.format("Test Alert", _score_result(6.0), sample_iocs)
        assert "attachments" in msg
        assert isinstance(msg["attachments"], list)
        assert len(msg["attachments"]) > 0

    def test_attachment_has_blocks(self, formatter, sample_iocs):
        msg = formatter.format("Test Alert", _score_result(6.0), sample_iocs)
        attachment = msg["attachments"][0]
        assert "blocks" in attachment
        assert len(attachment["blocks"]) > 0

    def test_critical_colour_is_danger(self, formatter, sample_iocs):
        msg = formatter.format("Test", _score_result(8.5), sample_iocs)
        assert msg["attachments"][0]["color"] == "danger"

    def test_high_colour_is_danger(self, formatter, sample_iocs):
        msg = formatter.format("Test", _score_result(6.0), sample_iocs)
        assert msg["attachments"][0]["color"] == "danger"

    def test_medium_colour_is_warning(self, formatter, sample_iocs):
        msg = formatter.format("Test", _score_result(4.0), sample_iocs)
        assert msg["attachments"][0]["color"] == "warning"

    def test_low_colour_is_good(self, formatter, sample_iocs):
        msg = formatter.format("Test", _score_result(1.5), sample_iocs)
        assert msg["attachments"][0]["color"] == "good"

    def test_thehive_url_button_present_when_provided(self, formatter, sample_iocs):
        msg = formatter.format(
            "Test", _score_result(8.0), sample_iocs,
            thehive_case_url="https://thehive.example.com/cases/~123"
        )
        # Find the actions block
        blocks = msg["attachments"][0]["blocks"]
        action_block = next((b for b in blocks if b["type"] == "actions"), None)
        assert action_block is not None
        urls = [e.get("url") for e in action_block.get("elements", [])]
        assert "https://thehive.example.com/cases/~123" in urls

    def test_no_thehive_button_when_no_url(self, formatter, sample_iocs):
        msg = formatter.format("Test", _score_result(8.0), sample_iocs)
        blocks = msg["attachments"][0]["blocks"]
        action_block = next((b for b in blocks if b["type"] == "actions"), None)
        assert action_block is not None
        urls = [e.get("url") for e in action_block.get("elements", [])]
        assert not any(urls)  # no URLs at all

    def test_fallback_text_present(self, formatter, sample_iocs):
        msg = formatter.format("Critical Phishing Alert", _score_result(9.0), sample_iocs)
        assert "text" in msg
        assert "Critical Phishing Alert" in msg["text"]

    def test_enrichment_section_when_provided(self, formatter, sample_iocs):
        enrichment = {
            "vt_result": {"malicious": 50, "total": 75, "reputation": -60},
            "abuse_result": {"confidence": 85, "total_reports": 200},
        }
        msg = formatter.format("Test", _score_result(7.5), sample_iocs,
                                enrichment_summary=enrichment)
        # The message should be richer with enrichment data
        all_text = str(msg)
        assert "VirusTotal" in all_text
        assert "AbuseIPDB" in all_text
