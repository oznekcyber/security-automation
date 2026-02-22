#!/usr/bin/env python3
"""
Shuffle SOAR webhook alert simulator.

Fires realistic Splunk Notable Event payloads at a Shuffle webhook endpoint
so you can test the phishing-response workflow without real Splunk data.

All IOCs in the test payloads are FAKE and constructed to look realistic
(valid format, correct length) but do NOT correspond to real malicious
infrastructure.

Usage
-----
::

    # Fire the default phishing scenario at localhost:
    python simulate_alert.py

    # Specify a different webhook URL:
    python simulate_alert.py --url http://localhost:3001/api/v1/hooks/abc123

    # Fire all scenarios sequentially:
    python simulate_alert.py --scenario all

    # Fire a specific scenario:
    python simulate_alert.py --scenario malware

Available scenarios: phishing, malware, network

Requirements: requests (pip install requests)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from typing import Any

try:
    import requests
except ImportError:
    print("ERROR: 'requests' not installed. Run: pip install requests")
    sys.exit(1)

# ---------------------------------------------------------------------------
# ANSI colour helpers for terminal output
# ---------------------------------------------------------------------------

_RESET = "\033[0m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_GREEN = "\033[32m"
_CYAN = "\033[36m"
_BOLD = "\033[1m"


def _c(colour: str, text: str) -> str:
    """Wrap *text* in ANSI colour codes (skipped on non-TTY)."""
    if not sys.stdout.isatty():
        return text
    return f"{colour}{text}{_RESET}"


def _print_section(title: str) -> None:
    width = 60
    print(f"\n{_c(_BOLD, '=' * width)}")
    print(f"{_c(_BOLD, _CYAN, title)}")
    print(_c(_BOLD, "=" * width))


# ---------------------------------------------------------------------------
# Fake (but realistic-looking) test payloads
# ---------------------------------------------------------------------------

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


SCENARIOS: dict[str, dict[str, Any]] = {

    "phishing": {
        "name": "Phishing Campaign — Credential Harvesting",
        "payload": {
            "alert_title": "Phishing email from spoofed-it@corp-helpdesk.xyz",
            "alert_type": "phishing",
            "severity": "high",
            "timestamp": _ts(),
            "splunk_search_name": "SOC - Phishing Detection - Email Analysis",
            "splunk_sid": "rt_scheduler__admin__SplunkSOC__RMD5abc123def456_at_1700000000_1",
            "alert_text": (
                "Phishing email detected targeting finance department. "
                "Sender: spoofed-it@corp-helpdesk.xyz "
                "Reply-To: attacker@evil-infrastructure.ru "
                "Originating IP: 185.220.101.42 (internal relay: 192.168.1.50) "
                "Phishing URL: http://corp-helpdesk-portal.xyz/verify?token=abc123def456 "
                "Attachment SHA256: "
                "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a "
                "Attachment MD5: 44d88612fea8a8f36de82e1278abb02f "
                "Targeted users: alice@corp.com, bob@corp.com"
            ),
            "source_ip": "185.220.101.42",
            "dest_ip": "10.1.2.34",
            "user": "alice@corp.com",
            "host": "WORKSTATION-042",
            "count": 23,
            "raw_event": {
                "subject": "URGENT: Your account will be suspended",
                "sender": "spoofed-it@corp-helpdesk.xyz",
                "recipients": ["alice@corp.com", "bob@corp.com"],
                "attachment_count": 1,
            },
        },
    },

    "malware": {
        "name": "Malware Detection — Suspicious Executable",
        "payload": {
            "alert_title": "Suspected malware execution on WORKSTATION-099",
            "alert_type": "malware",
            "severity": "critical",
            "timestamp": _ts(),
            "splunk_search_name": "SOC - Malware - Endpoint Detection Alert",
            "splunk_sid": "rt_scheduler__admin__SplunkSOC__RMD9xyz789_at_1700000100_1",
            "alert_text": (
                "Endpoint protection flagged suspicious binary execution. "
                "Host: WORKSTATION-099 User: charlie@corp.com "
                "Process: C:\\Users\\charlie\\AppData\\Local\\Temp\\svchost32.exe "
                "File SHA256: "
                "b94f6f125c79e3a5ffaa826f584c10d52ada669e6762051b826b55776d05a8ad "
                "File MD5: 5d41402abc4b2a76b9719d911017c592 "
                "C2 connection to 198.51.100.77 on port 4444 "
                "DNS query for malware-c2-domain.io "
                "Network beacon every 300s detected"
            ),
            "source_ip": "198.51.100.77",
            "dest_ip": "10.1.99.1",
            "user": "charlie@corp.com",
            "host": "WORKSTATION-099",
            "count": 1,
            "raw_event": {
                "file_path": "C:\\Users\\charlie\\AppData\\Local\\Temp\\svchost32.exe",
                "parent_process": "explorer.exe",
                "command_line": "svchost32.exe -s hidden",
                "av_signature": "Trojan.Generic.12345678",
            },
        },
    },

    "network": {
        "name": "Network Anomaly — Potential Data Exfiltration",
        "payload": {
            "alert_title": "Anomalous outbound data transfer from SERVER-DB01",
            "alert_type": "network_anomaly",
            "severity": "medium",
            "timestamp": _ts(),
            "splunk_search_name": "SOC - Network - Large Outbound Transfer Detected",
            "splunk_sid": "rt_scheduler__admin__SplunkSOC__RMD3net456_at_1700000200_1",
            "alert_text": (
                "Unusual outbound data volume detected from database server. "
                "Source: SERVER-DB01 (10.1.5.10) "
                "Destination: 203.0.113.99 (suspicious-cloud-storage.example.net) "
                "Protocol: HTTPS (port 443) "
                "Transfer volume: 4.7 GB in 15 minutes (baseline: ~50 MB/hour) "
                "Time window: 02:15-02:30 UTC (outside business hours) "
                "No associated change ticket found"
            ),
            "source_ip": "203.0.113.99",
            "dest_ip": "10.1.5.10",
            "user": "svc-backup@corp.com",
            "host": "SERVER-DB01",
            "bytes_out": 5046586368,
            "count": 1,
            "raw_event": {
                "bytes_out": 5046586368,
                "duration_seconds": 900,
                "dest_domain": "suspicious-cloud-storage.example.net",
                "ssl_issuer": "Let's Encrypt",
            },
        },
    },
}


# ---------------------------------------------------------------------------
# Fire a payload
# ---------------------------------------------------------------------------

def fire_scenario(
    scenario_key: str,
    webhook_url: str,
    timeout: int = 10,
) -> None:
    """Send a single scenario payload to *webhook_url* and print results."""
    scenario = SCENARIOS[scenario_key]
    payload = scenario["payload"]

    _print_section(f"Scenario: {scenario['name']}")

    print(f"\n{_c(_CYAN, 'Target URL:')} {webhook_url}")
    print(f"{_c(_CYAN, 'Alert type:')} {payload['alert_type']}")
    print(f"{_c(_CYAN, 'Severity:')}   {payload['severity']}")
    print(f"\n{_c(_CYAN, 'Payload (JSON):')}")
    print(json.dumps(payload, indent=2))

    print(f"\n{_c(_YELLOW, '→ Sending request...')}")

    try:
        response = requests.post(
            webhook_url,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-Source": "simulate_alert.py",
                "X-Scenario": scenario_key,
            },
            timeout=timeout,
        )

        status_colour = _GREEN if response.status_code < 300 else _RED
        print(
            f"{_c(status_colour, f'← HTTP {response.status_code}')} "
            f"({len(response.content)} bytes)"
        )

        # Try to pretty-print JSON response
        try:
            resp_json = response.json()
            print(f"\n{_c(_CYAN, 'Response body:')}")
            print(json.dumps(resp_json, indent=2))
        except ValueError:
            body = response.text[:500]
            if body:
                print(f"\n{_c(_CYAN, 'Response body (raw):')}")
                print(body)

    except requests.exceptions.ConnectionError:
        print(
            _c(_RED, f"ERROR: Could not connect to {webhook_url}\n")
            + "Is the Shuffle backend running? Try: docker-compose up -d shuffle-backend"
        )
    except requests.exceptions.Timeout:
        print(_c(_RED, f"ERROR: Request timed out after {timeout}s"))
    except Exception as exc:
        print(_c(_RED, f"ERROR: {exc}"))


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fire test alert payloads at a Shuffle SOAR webhook",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--url",
        default="http://localhost:3001/api/v1/hooks/placeholder",
        help="Shuffle webhook URL (default: %(default)s)",
    )
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS.keys()) + ["all"],
        default="phishing",
        help="Alert scenario to fire (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Delay in seconds between scenarios when using --scenario all",
    )

    args = parser.parse_args()

    if args.scenario == "all":
        for key in SCENARIOS:
            fire_scenario(key, args.url, args.timeout)
            if key != list(SCENARIOS.keys())[-1]:
                print(f"\n{_c(_YELLOW, f'Waiting {args.delay}s before next scenario...')}")
                time.sleep(args.delay)
    else:
        fire_scenario(args.scenario, args.url, args.timeout)

    print(f"\n{_c(_GREEN, 'Done.')}\n")


if __name__ == "__main__":
    main()
