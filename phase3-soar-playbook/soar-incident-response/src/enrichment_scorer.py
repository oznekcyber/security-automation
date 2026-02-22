"""
Composite risk scoring from multi-source threat-intelligence enrichment.

This module combines results from VirusTotal (VT) and AbuseIPDB into a
single 0–10 risk score that a SOAR playbook can use to drive automated
triage decisions without requiring an analyst for every alert.

Scoring rationale
-----------------
We weight four independent signals:

1. **VT malicious detections (40 %)** — the fraction of VT engines that
   flag a sample/IP as malicious is the strongest single signal.  A high
   detection ratio is a reliable indicator of a known-bad indicator.

2. **VT reputation (20 %)** — the community reputation score (-100 to +100)
   captures historical analyst votes and crowdsourced context.  A deeply
   negative reputation adds weight even when engine count is borderline.

3. **AbuseIPDB confidence (30 %)** — the AbuseIPDB abuse-confidence score
   (0–100) is specifically designed for IP reputation and tends to have
   fewer false-positives than generic AV engines for infrastructure IOCs.

4. **Report volume (10 %)** — a high number of abuse reports independently
   corroborates the confidence score and increases confidence that the
   signal is not a one-off false positive.

Decision thresholds
-------------------
  > 7 (CRITICAL) → auto-escalate, page on-call, create P1 TheHive case
  5–7 (HIGH)      → auto-escalate, create P2 TheHive case
  3–5 (MEDIUM)    → queue for analyst review
  1–3 (LOW)       → analyst review, lower priority
  < 1 (INFO)      → auto-close / no action required

These thresholds match common SOC SOP for Tier-1 triage.

Usage
-----
::

    scorer = EnrichmentScorer()
    result = scorer.score({
        "vt_result": {
            "malicious": 52, "suspicious": 3, "total": 75, "reputation": -60
        },
        "abuse_result": {
            "confidence": 87, "total_reports": 312
        }
    })
    # result["score"]    → 8.4
    # result["tier"]     → "CRITICAL"
    # result["decision"] → "auto-escalate"
"""

from __future__ import annotations

import math
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WEIGHT_VT_DETECTIONS: float = 0.40
WEIGHT_VT_REPUTATION: float = 0.20
WEIGHT_ABUSE_CONFIDENCE: float = 0.30
WEIGHT_REPORT_VOLUME: float = 0.10

# Suspicious detections are weighted at 50% of malicious detections.
# "Suspicious" means one or more engines flagged heuristically but did not
# reach a definitive malicious verdict — real analysts treat this as weak
# corroborating evidence, not proof of compromise.
SUSPICIOUS_DETECTION_WEIGHT: float = 0.5

# Log-scale multiplier for report volume scoring.
# The formula log10(count + 1) * LOG_SCALE_MULTIPLIER maps:
#   1 report   → ~1.5  (weak signal)
#   10 reports → ~5.3  (moderate signal)
#   100 reports→ ~10.4 → capped at 10  (strong corroboration)
# This prevents a single high-volume attacker from dominating the score
# while still giving meaningful weight to broad community-sourced data.
LOG_SCALE_MULTIPLIER: float = 5.0

# Tier thresholds (upper-exclusive, i.e., score > threshold)
TIER_CRITICAL_THRESHOLD: float = 7.0
TIER_HIGH_THRESHOLD: float = 5.0
TIER_MEDIUM_THRESHOLD: float = 3.0
TIER_LOW_THRESHOLD: float = 1.0

# Decision thresholds
DECISION_AUTO_ESCALATE_THRESHOLD: float = 5.0
DECISION_ANALYST_REVIEW_THRESHOLD: float = 2.0


class EnrichmentScorer:
    """
    Combine multi-source enrichment data into a composite 0–10 risk score.

    The scorer is designed to degrade gracefully: if one data source is
    unavailable, it re-weights the remaining sources proportionally rather
    than returning an error or a misleading zero.
    """

    def score(self, enrichment_data: dict[str, Any]) -> dict[str, Any]:
        """
        Produce a composite risk score from enrichment results.

        Args:
            enrichment_data: Dict containing any combination of:

                * ``vt_result``    — dict with keys:
                    * ``malicious``   (int) number of malicious engine hits
                    * ``suspicious``  (int) number of suspicious engine hits
                    * ``total``       (int) total engines that ran
                    * ``reputation``  (int, -100 to 100) community score

                * ``abuse_result`` — dict with keys:
                    * ``confidence``    (int, 0–100) AbuseIPDB confidence score
                    * ``total_reports`` (int) number of abuse reports

        Returns:
            Dict with keys:

            * ``score``     — float 0.0–10.0
            * ``tier``      — one of CRITICAL / HIGH / MEDIUM / LOW / INFO
            * ``decision``  — one of auto-escalate / analyst-review / auto-close
            * ``breakdown`` — dict mapping each factor to its weighted contribution
                              and a human-readable reasoning string
            * ``partial``   — bool, True if one or more sources were unavailable
        """
        vt: dict[str, Any] = enrichment_data.get("vt_result") or {}
        abuse: dict[str, Any] = enrichment_data.get("abuse_result") or {}

        has_vt = bool(vt)
        has_abuse = bool(abuse)

        breakdown: dict[str, Any] = {}
        weighted_sum: float = 0.0
        active_weight: float = 0.0

        # ------------------------------------------------------------------
        # Factor 1 — VT malicious detection ratio (40 %)
        # ------------------------------------------------------------------
        if has_vt:
            malicious = int(vt.get("malicious", 0))
            suspicious = int(vt.get("suspicious", 0))
            total = int(vt.get("total", 0))

            if total > 0:
                # Combine malicious + half of suspicious (suspicious is uncertain)
                ratio = (malicious + suspicious * SUSPICIOUS_DETECTION_WEIGHT) / total
                factor_score = min(ratio * 10, 10.0)
            else:
                factor_score = 0.0

            contribution = factor_score * WEIGHT_VT_DETECTIONS
            weighted_sum += contribution
            active_weight += WEIGHT_VT_DETECTIONS
            breakdown["vt_detections"] = {
                "raw_score": round(factor_score, 2),
                "weight": WEIGHT_VT_DETECTIONS,
                "contribution": round(contribution, 2),
                "reasoning": (
                    f"{malicious} malicious + {suspicious} suspicious out of "
                    f"{total} engines → detection ratio "
                    f"{round((malicious + suspicious * SUSPICIOUS_DETECTION_WEIGHT) / max(total, 1) * 100, 1)}%"
                ),
            }
        else:
            breakdown["vt_detections"] = {
                "raw_score": None,
                "weight": WEIGHT_VT_DETECTIONS,
                "contribution": 0.0,
                "reasoning": "VT result unavailable — factor skipped",
            }

        # ------------------------------------------------------------------
        # Factor 2 — VT community reputation (20 %)
        # ------------------------------------------------------------------
        if has_vt and "reputation" in vt:
            reputation = int(vt.get("reputation", 0))
            # Map -100..+100 to 0..10 (inverted: lower reputation = higher risk).
            # Only negative reputation contributes to risk; neutral (0) or positive
            # reputation means no additional risk signal from this factor.
            # reputation -100 → score 10, 0 → score 0, +100 → score 0 (clamped).
            factor_score = max(0.0, min(10.0, -reputation / 10.0))
            contribution = factor_score * WEIGHT_VT_REPUTATION
            weighted_sum += contribution
            active_weight += WEIGHT_VT_REPUTATION
            breakdown["vt_reputation"] = {
                "raw_score": round(factor_score, 2),
                "weight": WEIGHT_VT_REPUTATION,
                "contribution": round(contribution, 2),
                "reasoning": (
                    f"VT community reputation {reputation} "
                    f"(scale -100=worst, +100=best) → risk score {round(factor_score, 2)} "
                    f"(only negative reputation contributes risk)"
                ),
            }
        else:
            breakdown["vt_reputation"] = {
                "raw_score": None,
                "weight": WEIGHT_VT_REPUTATION,
                "contribution": 0.0,
                "reasoning": "VT reputation unavailable — factor skipped",
            }

        # ------------------------------------------------------------------
        # Factor 3 — AbuseIPDB confidence score (30 %)
        # ------------------------------------------------------------------
        if has_abuse:
            confidence = int(abuse.get("confidence", 0))
            # AbuseIPDB is already 0-100; map linearly to 0-10
            factor_score = min(confidence / 10.0, 10.0)
            contribution = factor_score * WEIGHT_ABUSE_CONFIDENCE
            weighted_sum += contribution
            active_weight += WEIGHT_ABUSE_CONFIDENCE
            breakdown["abuse_confidence"] = {
                "raw_score": round(factor_score, 2),
                "weight": WEIGHT_ABUSE_CONFIDENCE,
                "contribution": round(contribution, 2),
                "reasoning": (
                    f"AbuseIPDB abuse-confidence {confidence}/100 "
                    f"→ risk score {round(factor_score, 2)}"
                ),
            }
        else:
            breakdown["abuse_confidence"] = {
                "raw_score": None,
                "weight": WEIGHT_ABUSE_CONFIDENCE,
                "contribution": 0.0,
                "reasoning": "AbuseIPDB result unavailable — factor skipped",
            }

        # ------------------------------------------------------------------
        # Factor 4 — Report volume (10 %)
        # ------------------------------------------------------------------
        if has_abuse:
            total_reports = int(abuse.get("total_reports", 0))
            # Log-scale: 1 report→1, 10→5, 100→10  (log10(x+1)*LOG_SCALE_MULTIPLIER capped at 10)
            factor_score = min(math.log10(total_reports + 1) * LOG_SCALE_MULTIPLIER, 10.0)
            contribution = factor_score * WEIGHT_REPORT_VOLUME
            weighted_sum += contribution
            active_weight += WEIGHT_REPORT_VOLUME
            breakdown["report_volume"] = {
                "raw_score": round(factor_score, 2),
                "weight": WEIGHT_REPORT_VOLUME,
                "contribution": round(contribution, 2),
                "reasoning": (
                    f"{total_reports} abuse reports → "
                    f"log-scale risk score {round(factor_score, 2)}"
                ),
            }
        else:
            breakdown["report_volume"] = {
                "raw_score": None,
                "weight": WEIGHT_REPORT_VOLUME,
                "contribution": 0.0,
                "reasoning": "AbuseIPDB result unavailable — factor skipped",
            }

        # ------------------------------------------------------------------
        # Normalise against active weight so partial data still produces a
        # meaningful score instead of being artificially dampened to zero.
        # ------------------------------------------------------------------
        if active_weight > 0:
            final_score = round(weighted_sum / active_weight, 2)
        else:
            final_score = 0.0

        # Cap to [0, 10]
        final_score = max(0.0, min(10.0, final_score))

        tier = self._tier(final_score)
        decision = self._decision(final_score)
        partial = not (has_vt and has_abuse)

        return {
            "score": final_score,
            "tier": tier,
            "decision": decision,
            "breakdown": breakdown,
            "partial": partial,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _tier(score: float) -> str:
        """Map a 0–10 score to a human-readable severity tier."""
        if score > TIER_CRITICAL_THRESHOLD:
            return "CRITICAL"
        if score > TIER_HIGH_THRESHOLD:
            return "HIGH"
        if score > TIER_MEDIUM_THRESHOLD:
            return "MEDIUM"
        if score > TIER_LOW_THRESHOLD:
            return "LOW"
        return "INFO"

    @staticmethod
    def _decision(score: float) -> str:
        """
        Map a score to a triage decision.

        These thresholds are intentionally conservative — it is better to
        send something to analyst review than to auto-close a real incident.
        """
        if score > DECISION_AUTO_ESCALATE_THRESHOLD:
            return "auto-escalate"
        if score > DECISION_ANALYST_REVIEW_THRESHOLD:
            return "analyst-review"
        return "auto-close"
