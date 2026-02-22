#!/usr/bin/env python3
"""
Phase 2 — Splunk Log Ingestion Pipeline

Parses structured security log events and forwards them to
Splunk via the HTTP Event Collector (HEC) API.

Usage:
    python main.py                   # Process logs from stdin
    python main.py --file events.log # Process a log file
    python main.py --demo            # Run with built-in sample data
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

SAMPLE_EVENTS = [
    {
        "timestamp": "2024-02-18T12:00:00Z",
        "source": "firewall",
        "severity": "high",
        "src_ip": "185.220.101.1",
        "dst_ip": "10.0.0.5",
        "action": "blocked",
        "bytes": 1024,
    },
    {
        "timestamp": "2024-02-18T12:01:00Z",
        "source": "ids",
        "severity": "critical",
        "signature": "ET MALWARE TorrentLocker CnC Beacon",
        "src_ip": "192.168.1.100",
        "dst_ip": "45.33.32.156",
        "action": "alert",
    },
]


def normalize_event(raw: dict) -> dict:
    """Normalize a raw log event to a common schema."""
    return {
        "time": raw.get("timestamp"),
        "source": raw.get("source", "unknown"),
        "severity": raw.get("severity", "info"),
        "fields": {k: v for k, v in raw.items() if k not in ("timestamp", "source", "severity")},
    }


def forward_to_splunk(events: list[dict], hec_url: str, hec_token: str) -> bool:
    """Forward normalized events to Splunk HEC (stub — implement with requests)."""
    logger.info("Forwarding %d event(s) to Splunk HEC at %s", len(events), hec_url)
    logger.info("Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN to enable real forwarding.")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Splunk Log Ingestion Pipeline")
    parser.add_argument("--file", metavar="FILE", help="Log file to process")
    parser.add_argument("--demo", action="store_true", help="Run with sample data")
    args = parser.parse_args()

    hec_url = os.getenv("SPLUNK_HEC_URL", "")
    hec_token = os.getenv("SPLUNK_HEC_TOKEN", "")

    if args.demo:
        logger.info("Running in DEMO mode with %d sample events", len(SAMPLE_EVENTS))
        events = SAMPLE_EVENTS
    elif args.file:
        with open(args.file, encoding="utf-8") as fh:
            events = json.load(fh)
    else:
        logger.info("Reading events from stdin (Ctrl+D to finish)...")
        events = json.load(sys.stdin)

    normalized = [normalize_event(e) for e in events]
    logger.info("Normalized %d event(s)", len(normalized))

    if hec_url and hec_token:
        forward_to_splunk(normalized, hec_url, hec_token)
    else:
        print(json.dumps(normalized, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
