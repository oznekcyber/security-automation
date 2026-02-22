#!/usr/bin/env python3
"""
Security Alert Normalizer — CLI entry point.

Usage examples
--------------
# Enrich a set of IPs with both VirusTotal and AbuseIPDB
python main.py --ips 8.8.8.8 1.1.1.1 185.220.101.1

# Enrich file hashes (VirusTotal only)
python main.py --hashes 44d88612fea8a8f36de82e1278abb02f

# Save output to a custom file and POST to a webhook
python main.py --ips 45.33.32.156 --output results.json \\
               --webhook https://webhook.site/your-uuid

# Use verbose logging to see every API call
python main.py --ips 8.8.8.8 --log-level DEBUG

# Apply a jq filter to the output
python main.py --ips 8.8.8.8 --jq '.[] | select(.verdict == "malicious")'

# Dry-run using built-in mock data (no real API calls)
python main.py --demo
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from src.utils.config import load_config, Config
from src.utils.logger import configure_logging, get_logger
from src.collectors import virustotal as vt_collector
from src.collectors import abuseipdb as abuse_collector
from src.transformers.normalizer import (
    normalize_virustotal,
    normalize_abuseipdb,
    apply_jq_filter,
    serialize_alerts,
)
from src.transformers.schema import IndicatorType, NormalizedAlert
from src.outputs.webhook import send_webhook


logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Mock / demo data
# ---------------------------------------------------------------------------

MOCK_VT_IP_RESPONSE: dict = {
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
                "malicious": 18,
                "suspicious": 2,
                "harmless": 60,
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

MOCK_VT_HASH_RESPONSE: dict = {
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

MOCK_ABUSE_RESPONSE: dict = {
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


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

def run_pipeline(cfg: Config, jq_expression: Optional[str] = None) -> list[NormalizedAlert]:
    """
    Execute the full enrichment + normalization pipeline.

    1. For each IP: call VT and AbuseIPDB, normalize both responses.
    2. For each file hash: call VT, normalize.
    3. Optionally apply a jq filter and log the result.

    Returns the list of NormalizedAlert objects (pre-filter).
    """
    alerts: list[NormalizedAlert] = []

    for ip in cfg.ip_addresses:
        # VirusTotal IP enrichment
        try:
            raw_vt = vt_collector.fetch_ip_report(ip, cfg)
            if raw_vt:
                alert = normalize_virustotal(raw_vt, ip, IndicatorType.IP)
                alerts.append(alert)
        except PermissionError as exc:
            logger.error("VT auth error for %s: %s", ip, exc)
        except Exception as exc:
            logger.error("VT enrichment failed for %s: %s", ip, exc)

        # AbuseIPDB IP enrichment
        try:
            raw_abuse = abuse_collector.fetch_ip_report(ip, cfg)
            if raw_abuse:
                alert = normalize_abuseipdb(raw_abuse, ip)
                alerts.append(alert)
        except PermissionError as exc:
            logger.error("AbuseIPDB auth error for %s: %s", ip, exc)
        except Exception as exc:
            logger.error("AbuseIPDB enrichment failed for %s: %s", ip, exc)

    for h in cfg.file_hashes:
        try:
            raw_vt = vt_collector.fetch_file_report(h, cfg)
            if raw_vt:
                alert = normalize_virustotal(raw_vt, h, IndicatorType.FILE_HASH)
                alerts.append(alert)
        except PermissionError as exc:
            logger.error("VT auth error for hash %s: %s", h, exc)
        except Exception as exc:
            logger.error("VT enrichment failed for hash %s: %s", h, exc)

    # Optional jq filtering — apply to serialized dicts, log result
    if jq_expression and alerts:
        try:
            alert_dicts = [a.to_dict() for a in alerts]
            filtered = apply_jq_filter(alert_dicts, jq_expression)
            logger.info("jq filter result: %s", json.dumps(filtered, indent=2, default=str))
        except (ValueError, RuntimeError) as exc:
            logger.warning("jq filter failed: %s", exc)

    return alerts


def run_demo(jq_expression: Optional[str] = None) -> list[NormalizedAlert]:
    """
    Run the pipeline against built-in mock data — no API keys required.

    Useful for verifying the normalization logic and schema output
    without burning API quota.
    """
    logger.info("Running in DEMO mode with mock data — no real API calls")
    alerts: list[NormalizedAlert] = [
        normalize_virustotal(MOCK_VT_IP_RESPONSE, "185.220.101.1", IndicatorType.IP),
        normalize_abuseipdb(MOCK_ABUSE_RESPONSE, "185.220.101.1"),
        normalize_virustotal(
            MOCK_VT_HASH_RESPONSE,
            "44d88612fea8a8f36de82e1278abb02f",
            IndicatorType.FILE_HASH,
        ),
    ]

    if jq_expression:
        try:
            alert_dicts = [a.to_dict() for a in alerts]
            filtered = apply_jq_filter(alert_dicts, jq_expression)
            logger.info("jq filter result:\n%s", json.dumps(filtered, indent=2, default=str))
        except (ValueError, RuntimeError) as exc:
            logger.warning("jq filter failed: %s", exc)

    return alerts


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-alert-normalizer",
        description=(
            "Fetch threat intelligence from VirusTotal and AbuseIPDB, "
            "normalize the responses into a unified schema, and optionally "
            "ship the results to a webhook endpoint."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    indicators = parser.add_argument_group("Indicators")
    indicators.add_argument(
        "--ips",
        nargs="+",
        metavar="IP",
        default=[],
        help="One or more IP addresses to enrich",
    )
    indicators.add_argument(
        "--hashes",
        nargs="+",
        metavar="HASH",
        default=[],
        help="One or more file hashes (MD5/SHA-1/SHA-256) to enrich",
    )

    output = parser.add_argument_group("Output")
    output.add_argument(
        "--output",
        metavar="FILE",
        default="normalized_alerts.json",
        help="Path to write the normalized JSON report (default: normalized_alerts.json)",
    )
    output.add_argument(
        "--webhook",
        metavar="URL",
        default="",
        help="Webhook URL to POST the normalized alerts to",
    )
    output.add_argument(
        "--jq",
        metavar="EXPR",
        default="",
        help="jq expression to apply to the output (result is logged, not saved)",
    )

    misc = parser.add_argument_group("Miscellaneous")
    misc.add_argument(
        "--demo",
        action="store_true",
        help="Run with built-in mock data — no API keys or network required",
    )
    misc.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging verbosity (default: INFO)",
    )
    misc.add_argument(
        "--log-file",
        metavar="FILE",
        default="",
        help="Optional file to write log output to",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    configure_logging(
        level=args.log_level,
        log_file=args.log_file or None,
    )

    if not args.demo and not args.ips and not args.hashes:
        parser.error("Provide at least one --ips or --hashes value, or use --demo")

    # -----------------------------------------------------------------------
    # Demo mode
    # -----------------------------------------------------------------------
    if args.demo:
        alerts = run_demo(jq_expression=args.jq or None)
    else:
        # -----------------------------------------------------------------------
        # Live mode — load config (raises if keys are missing)
        # -----------------------------------------------------------------------
        try:
            cfg = load_config(
                ip_addresses=args.ips,
                file_hashes=args.hashes,
                webhook_url=args.webhook,
                output_file=args.output,
            )
        except ValueError as exc:
            logger.error("Configuration error: %s", exc)
            return 1

        alerts = run_pipeline(cfg, jq_expression=args.jq or None)

    if not alerts:
        logger.warning("No alerts were produced — check your indicators and API keys")
        return 0

    # -----------------------------------------------------------------------
    # Serialize and write to file
    # -----------------------------------------------------------------------
    output_path = args.output
    json_output = serialize_alerts(alerts)
    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(json_output)
        logger.info("Wrote %d alert(s) to %s", len(alerts), output_path)
    except OSError as exc:
        logger.error("Failed to write output file %s: %s", output_path, exc)
        return 1

    # -----------------------------------------------------------------------
    # Webhook delivery (optional)
    # -----------------------------------------------------------------------
    webhook_url = args.webhook
    if webhook_url:
        alert_dicts = [a.to_dict() for a in alerts]
        success = send_webhook(
            alert_dicts,
            webhook_url=webhook_url,
        )
        if not success:
            logger.warning("Webhook delivery failed — alerts were still written to file")

    # Print summary to stdout for quick review
    print(json_output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
