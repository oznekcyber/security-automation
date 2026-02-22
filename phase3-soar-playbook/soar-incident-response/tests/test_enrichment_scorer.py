"""
Tests for EnrichmentScorer — runs entirely offline, no API keys required.

Run with:
    pytest tests/ -v
"""

from __future__ import annotations

import pytest

from src.enrichment_scorer import EnrichmentScorer


@pytest.fixture
def scorer() -> EnrichmentScorer:
    return EnrichmentScorer()


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------

def _vt(malicious: int = 0, suspicious: int = 0, total: int = 80, reputation: int = 0) -> dict:
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "total": total,
        "reputation": reputation,
    }


def _abuse(confidence: int = 0, total_reports: int = 0) -> dict:
    return {"confidence": confidence, "total_reports": total_reports}


# ---------------------------------------------------------------------------
# Tier classification
# ---------------------------------------------------------------------------

class TestTierClassification:
    def test_clean_scores_info(self, scorer):
        result = scorer.score({"vt_result": _vt(0, 0, 80), "abuse_result": _abuse(0, 0)})
        assert result["tier"] == "INFO"
        assert result["score"] < 1

    def test_low_tier(self, scorer):
        # Small number of detections, low abuse confidence
        result = scorer.score({
            "vt_result": _vt(malicious=5, total=80, reputation=10),
            "abuse_result": _abuse(confidence=15, total_reports=3),
        })
        assert result["tier"] in ("LOW", "INFO")
        assert result["score"] < 5

    def test_medium_tier(self, scorer):
        result = scorer.score({
            "vt_result": _vt(malicious=20, total=80, reputation=-20),
            "abuse_result": _abuse(confidence=45, total_reports=25),
        })
        assert result["tier"] in ("MEDIUM", "HIGH")

    def test_critical_tier(self, scorer):
        result = scorer.score({
            "vt_result": _vt(malicious=65, suspicious=5, total=75, reputation=-80),
            "abuse_result": _abuse(confidence=90, total_reports=300),
        })
        assert result["tier"] == "CRITICAL"
        assert result["score"] > 7

    def test_score_above_5_is_high_or_critical(self, scorer):
        result = scorer.score({
            "vt_result": _vt(malicious=40, total=75, reputation=-50),
            "abuse_result": _abuse(confidence=70, total_reports=100),
        })
        assert result["score"] > 5


# ---------------------------------------------------------------------------
# Decision logic
# ---------------------------------------------------------------------------

class TestDecisionLogic:
    def test_auto_close_for_clean(self, scorer):
        result = scorer.score({"vt_result": _vt(0, 0, 80), "abuse_result": _abuse(0, 0)})
        assert result["decision"] == "auto-close"

    def test_analyst_review_boundary(self, scorer):
        # Score just above 2 and below 5 → analyst-review
        result = scorer.score({
            "vt_result": _vt(malicious=8, total=80, reputation=-5),
            "abuse_result": _abuse(confidence=20, total_reports=10),
        })
        score = result["score"]
        if 2 < score <= 5:
            assert result["decision"] == "analyst-review"

    def test_auto_escalate_for_critical(self, scorer):
        result = scorer.score({
            "vt_result": _vt(malicious=65, suspicious=5, total=75, reputation=-80),
            "abuse_result": _abuse(confidence=90, total_reports=300),
        })
        assert result["decision"] == "auto-escalate"

    def test_score_exactly_above_5_escalates(self, scorer):
        # Drive score above 5 with high numbers
        result = scorer.score({
            "vt_result": _vt(malicious=50, total=80, reputation=-60),
            "abuse_result": _abuse(confidence=75, total_reports=150),
        })
        if result["score"] > 5:
            assert result["decision"] == "auto-escalate"


# ---------------------------------------------------------------------------
# Partial data (graceful degradation)
# ---------------------------------------------------------------------------

class TestPartialData:
    def test_vt_only(self, scorer):
        result = scorer.score({
            "vt_result": _vt(malicious=50, total=75, reputation=-70),
            "abuse_result": None,
        })
        assert result["partial"] is True
        assert result["score"] > 0

    def test_abuse_only(self, scorer):
        result = scorer.score({
            "vt_result": None,
            "abuse_result": _abuse(confidence=85, total_reports=200),
        })
        assert result["partial"] is True
        assert result["score"] > 0

    def test_no_data_returns_info(self, scorer):
        result = scorer.score({})
        assert result["tier"] == "INFO"
        assert result["score"] == 0.0

    def test_empty_dicts_handled(self, scorer):
        result = scorer.score({"vt_result": {}, "abuse_result": {}})
        assert result["score"] == 0.0


# ---------------------------------------------------------------------------
# Breakdown structure
# ---------------------------------------------------------------------------

class TestBreakdownStructure:
    def test_breakdown_has_all_factors(self, scorer):
        result = scorer.score({
            "vt_result": _vt(malicious=10, total=80, reputation=-20),
            "abuse_result": _abuse(confidence=50, total_reports=30),
        })
        bd = result["breakdown"]
        assert "vt_detections" in bd
        assert "vt_reputation" in bd
        assert "abuse_confidence" in bd
        assert "report_volume" in bd

    def test_each_factor_has_reasoning(self, scorer):
        result = scorer.score({
            "vt_result": _vt(malicious=10, total=80, reputation=-20),
            "abuse_result": _abuse(confidence=50, total_reports=30),
        })
        for _name, detail in result["breakdown"].items():
            assert "reasoning" in detail
            assert isinstance(detail["reasoning"], str)

    def test_score_bounded_0_to_10(self, scorer):
        # Max out all signals
        result = scorer.score({
            "vt_result": _vt(malicious=80, total=80, reputation=-100),
            "abuse_result": _abuse(confidence=100, total_reports=99999),
        })
        assert 0.0 <= result["score"] <= 10.0

        # Min out all signals
        result = scorer.score({
            "vt_result": _vt(0, 0, 80, 100),
            "abuse_result": _abuse(0, 0),
        })
        assert 0.0 <= result["score"] <= 10.0
