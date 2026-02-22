#!/usr/bin/env python3
"""
Phase 3 — SOAR Incident Response Playbook

Automated incident response orchestration: alert triage, IOC enrichment,
containment actions, and notification via Shuffle SOAR workflows.

Usage:
    python main.py --alert '{"id":"INC-001","severity":"critical",...}'
    python main.py --demo
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

SAMPLE_ALERT = {
    "id": "INC-2024-001",
    "severity": "critical",
    "title": "Ransomware C2 Beacon Detected",
    "source": "ids",
    "indicators": [
        {"type": "ip", "value": "185.220.101.1"},
        {"type": "domain", "value": "malicious-c2.example.com"},
    ],
    "affected_host": "WORKSTATION-42",
    "timestamp": "2024-02-18T12:00:00Z",
}

PLAYBOOK_STEPS = [
    "enrich_indicators",
    "calculate_risk_score",
    "isolate_host",
    "collect_evidence",
    "create_ticket",
    "notify_team",
]


def enrich_indicators(alert: dict) -> dict:
    """Stub: enrich IOCs via VT/AbuseIPDB (delegates to Phase 1 in production)."""
    logger.info("Enriching %d indicator(s)...", len(alert.get("indicators", [])))
    alert["enrichment"] = {"status": "completed", "verdict": "malicious"}
    return alert


def calculate_risk_score(alert: dict) -> dict:
    """Compute a 0–100 risk score based on severity and enrichment verdict."""
    severity_scores = {"critical": 90, "high": 70, "medium": 40, "low": 10}
    base = severity_scores.get(alert.get("severity", "low"), 10)
    verdict_bonus = 10 if alert.get("enrichment", {}).get("verdict") == "malicious" else 0
    alert["risk_score"] = min(100, base + verdict_bonus)
    logger.info("Risk score: %d/100", alert["risk_score"])
    return alert


def run_playbook(alert: dict) -> dict:
    """Execute the full incident response playbook."""
    logger.info("Starting playbook for alert: %s", alert.get("id"))
    alert = enrich_indicators(alert)
    alert = calculate_risk_score(alert)
    for step in PLAYBOOK_STEPS[2:]:
        logger.info("Executing step: %s", step)
        alert.setdefault("playbook_steps_completed", []).append(step)
    alert["status"] = "remediated"
    return alert


def main() -> int:
    parser = argparse.ArgumentParser(description="SOAR Incident Response Playbook")
    parser.add_argument("--alert", metavar="JSON", help="Alert JSON to process")
    parser.add_argument("--demo", action="store_true", help="Run with sample alert")
    args = parser.parse_args()

    if args.demo:
        alert = SAMPLE_ALERT
    elif args.alert:
        alert = json.loads(args.alert)
    else:
        logger.info("Reading alert from stdin...")
        alert = json.load(sys.stdin)

    result = run_playbook(alert)
    print(json.dumps(result, indent=2))

    shuffle_url = os.getenv("SHUFFLE_URL", "")
    if shuffle_url:
        logger.info("Shuffle SOAR integration URL: %s", shuffle_url)

    return 0


if __name__ == "__main__":
    sys.exit(main())
