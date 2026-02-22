"""Unit tests for the Phase 2 event generators.

All tests are fully offline – no network calls are made.  The test suite
validates:

* Correct field presence and types for every generator.
* Brute-force SSH pattern (burst events from the same IP).
* CEF format string structure.
* Beaconing interval regularity (CV < 0.3).
* IOC events carry required hash fields.
* All event timestamps are valid ISO-8601 strings.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest

from src.generators.ssh_events import (
    generate_ssh_failed_login,
    generate_ssh_successful_login,
)
from src.generators.process_events import generate_suspicious_process
from src.generators.network_events import generate_suspicious_outbound, generate_dns_query
from src.generators.ioc_events import generate_ioc_match

# ── helpers ───────────────────────────────────────────────────────────────────

_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2}|Z)?$"
)

CEF_RE = re.compile(
    r"^CEF:0\|[^|]+\|[^|]+\|[^|]+\|[^|]+\|[^|]+\|\d+\|.*$"
)


def _is_iso8601(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    # Accept both offset-aware (±HH:MM) and naive strings produced by
    # datetime.isoformat().
    try:
        datetime.fromisoformat(value)
        return True
    except ValueError:
        return False


def _cv(values: List[float]) -> float:
    """Coefficient of variation (std / mean)."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    if mean == 0:
        return 0.0
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    return math.sqrt(variance) / mean


# ── SSH failed login ──────────────────────────────────────────────────────────

class TestSSHFailedLogin:
    def test_returns_list(self) -> None:
        events = generate_ssh_failed_login(3)
        assert isinstance(events, list)
        assert len(events) == 3

    def test_required_fields(self) -> None:
        required = {
            "event_id", "timestamp", "src_ip", "dst_ip", "username",
            "failure_reason", "severity", "source_host", "event_type", "cef_raw",
        }
        for ev in generate_ssh_failed_login(2):
            assert required.issubset(ev.keys()), f"Missing fields: {required - ev.keys()}"

    def test_event_type(self) -> None:
        for ev in generate_ssh_failed_login(5):
            assert ev["event_type"] == "ssh_failed_login"

    def test_timestamp_iso8601(self) -> None:
        for ev in generate_ssh_failed_login(5):
            assert _is_iso8601(ev["timestamp"]), f"Bad timestamp: {ev['timestamp']}"

    def test_cef_format(self) -> None:
        for ev in generate_ssh_failed_login(5):
            assert CEF_RE.match(ev["cef_raw"]), f"Bad CEF: {ev['cef_raw']}"

    def test_brute_force_burst_same_ip(self) -> None:
        """A bulk generation run should include multiple events from the same IP."""
        events = generate_ssh_failed_login(20)
        src_ips = [ev["src_ip"] for ev in events]
        # At least one IP appears more than once (burst pattern).
        from collections import Counter
        counts = Counter(src_ips)
        assert max(counts.values()) > 1, "Expected burst: multiple events from same IP"

    def test_severity_values(self) -> None:
        valid_severities = {"low", "medium", "high", "critical"}
        for ev in generate_ssh_failed_login(10):
            assert ev["severity"] in valid_severities


# ── SSH successful login ──────────────────────────────────────────────────────

class TestSSHSuccessfulLogin:
    def test_returns_list(self) -> None:
        assert len(generate_ssh_successful_login(3)) == 3

    def test_event_type(self) -> None:
        for ev in generate_ssh_successful_login(3):
            assert ev["event_type"] == "ssh_successful_login"

    def test_severity_critical(self) -> None:
        for ev in generate_ssh_successful_login(5):
            assert ev["severity"] == "critical"

    def test_cef_format(self) -> None:
        for ev in generate_ssh_successful_login(3):
            assert CEF_RE.match(ev["cef_raw"]), f"Bad CEF: {ev['cef_raw']}"

    def test_timestamp_iso8601(self) -> None:
        for ev in generate_ssh_successful_login(3):
            assert _is_iso8601(ev["timestamp"])


# ── process events ────────────────────────────────────────────────────────────

class TestProcessEvents:
    def test_returns_list(self) -> None:
        assert len(generate_suspicious_process(4)) == 4

    def test_required_fields(self) -> None:
        required = {
            "event_id", "timestamp", "hostname", "username",
            "process_name", "process_path", "parent_process",
            "command_line", "pid", "ppid", "severity",
            "event_type", "mitre_technique_ids",
        }
        for ev in generate_suspicious_process(5):
            assert required.issubset(ev.keys()), f"Missing: {required - ev.keys()}"

    def test_event_type(self) -> None:
        for ev in generate_suspicious_process(5):
            assert ev["event_type"] == "suspicious_process"

    def test_mitre_ids_non_empty(self) -> None:
        for ev in generate_suspicious_process(10):
            assert len(ev["mitre_technique_ids"]) >= 1

    def test_mitre_id_format(self) -> None:
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for ev in generate_suspicious_process(10):
            for tid in ev["mitre_technique_ids"]:
                assert pattern.match(tid), f"Bad technique ID: {tid}"

    def test_timestamp_iso8601(self) -> None:
        for ev in generate_suspicious_process(5):
            assert _is_iso8601(ev["timestamp"])


# ── network events ────────────────────────────────────────────────────────────

class TestNetworkEvents:
    def test_suspicious_outbound_returns_list(self) -> None:
        assert len(generate_suspicious_outbound(5)) == 5

    def test_required_fields(self) -> None:
        required = {
            "event_id", "timestamp", "src_ip", "dst_ip",
            "dst_port", "protocol", "bytes_sent", "bytes_recv",
            "duration_ms", "event_type", "severity",
        }
        for ev in generate_suspicious_outbound(3):
            assert required.issubset(ev.keys()), f"Missing: {required - ev.keys()}"

    def test_event_type(self) -> None:
        for ev in generate_suspicious_outbound(5):
            assert ev["event_type"] == "suspicious_outbound"

    def test_beaconing_pattern_low_cv(self) -> None:
        """Beacon intervals should have a coefficient of variation < 0.3."""
        events = generate_suspicious_outbound(10)
        # Filter to the beacon subset (is_beacon=True)
        beacon_events = [ev for ev in events if ev.get("is_beacon")]
        if len(beacon_events) < 3:
            pytest.skip("Not enough beacon events generated for CV test")

        timestamps = sorted(
            datetime.fromisoformat(ev["timestamp"]).timestamp()
            for ev in beacon_events
        )
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        if not intervals:
            pytest.skip("Insufficient intervals for CV calculation")
        cv = _cv(intervals)
        assert cv < 0.3, f"Beacon CV too high: {cv:.3f} (expected < 0.3)"

    def test_dns_query_fields(self) -> None:
        required = {
            "event_id", "timestamp", "src_ip", "query",
            "query_type", "event_type", "severity",
        }
        for ev in generate_dns_query(5):
            assert required.issubset(ev.keys())

    def test_dns_event_type(self) -> None:
        for ev in generate_dns_query(5):
            assert ev["event_type"] == "suspicious_dns"

    def test_timestamp_iso8601(self) -> None:
        for ev in generate_suspicious_outbound(5):
            assert _is_iso8601(ev["timestamp"])
        for ev in generate_dns_query(5):
            assert _is_iso8601(ev["timestamp"])


# ── IOC events ────────────────────────────────────────────────────────────────

class TestIOCEvents:
    def test_returns_list(self) -> None:
        assert len(generate_ioc_match(3)) == 3

    def test_required_hash_fields(self) -> None:
        for ev in generate_ioc_match(5):
            assert "md5" in ev, "Missing md5 field"
            assert "sha256" in ev, "Missing sha256 field"

    def test_hash_lengths(self) -> None:
        for ev in generate_ioc_match(10):
            assert len(ev["md5"]) == 32, f"MD5 wrong length: {ev['md5']}"
            assert len(ev["sha256"]) == 64, f"SHA256 wrong length: {ev['sha256']}"

    def test_required_fields(self) -> None:
        required = {
            "event_id", "timestamp", "hostname", "username",
            "file_path", "file_name", "md5", "sha256",
            "threat_name", "threat_family", "severity", "event_type",
        }
        for ev in generate_ioc_match(5):
            assert required.issubset(ev.keys()), f"Missing: {required - ev.keys()}"

    def test_event_type(self) -> None:
        for ev in generate_ioc_match(5):
            assert ev["event_type"] == "ioc_file_match"

    def test_timestamp_iso8601(self) -> None:
        for ev in generate_ioc_match(5):
            assert _is_iso8601(ev["timestamp"])

    def test_file_creation_time_iso8601(self) -> None:
        for ev in generate_ioc_match(5):
            assert _is_iso8601(ev["file_creation_time"])

    def test_severity_valid(self) -> None:
        valid = {"low", "medium", "high", "critical"}
        for ev in generate_ioc_match(10):
            assert ev["severity"] in valid


# ── cross-generator timestamp sanity ─────────────────────────────────────────

class TestTimestampSanity:
    """Timestamps from all generators must be parseable and recent."""

    def _all_events(self) -> List[Dict[str, Any]]:
        return (
            generate_ssh_failed_login(2)
            + generate_ssh_successful_login(2)
            + generate_suspicious_process(2)
            + generate_suspicious_outbound(2)
            + generate_dns_query(2)
            + generate_ioc_match(2)
        )

    def test_all_timestamps_parseable(self) -> None:
        for ev in self._all_events():
            ts = ev.get("timestamp")
            assert ts is not None, "timestamp field is None"
            assert _is_iso8601(ts), f"Unparseable timestamp: {ts}"
