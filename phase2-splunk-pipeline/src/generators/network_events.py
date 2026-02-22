"""Suspicious network event generator.

Models two threat patterns:
* **C2 beaconing** – regular, low-jitter outbound connections to unusual
  destination ports, characteristic of implants phoning home.
* **Suspicious DNS queries** – DGA (domain-generation algorithm) style
  hostnames and long-subdomain exfiltration tunnels.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

_INTERNAL_SRC_IPS: List[str] = [
    "10.0.1.15", "10.0.2.33", "172.16.4.88",
    "192.168.1.42", "192.168.10.55",
]

# Known C2/malicious destination IPs (simulated)
_C2_IPS: List[str] = [
    "185.220.101.34",
    "194.165.16.5",
    "91.108.4.0",
    "45.142.212.100",
    "109.206.241.45",
]

_C2_DOMAINS: List[str] = [
    "update-service.ddns.net",
    "cdn-delivery.online",
    "telemetry-api.xyz",
    "log-collector.club",
    "metrics-push.top",
]

_UNUSUAL_PORTS: List[int] = [4444, 8080, 8443, 1337, 9001, 12345, 31337]

# DGA-style domain fragments
_DGA_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"
_DGA_TLDS = [".xyz", ".top", ".club", ".online", ".site", ".pw"]

_PROTOCOLS: List[str] = ["TCP", "UDP"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _dga_domain(length: int = 16) -> str:
    """Generate a random DGA-style hostname."""
    name = "".join(random.choices(_DGA_CHARS, k=length))
    return name + random.choice(_DGA_TLDS)


def _long_subdomain() -> str:
    """Generate a base32-encoded-looking exfiltration subdomain."""
    label = "".join(random.choices("abcdefghijklmnopqrstuvwxyz234567", k=32))
    return f"{label}.exfil-tunnel.net"


def generate_suspicious_outbound(count: int = 1) -> List[Dict[str, Any]]:
    """Generate *count* suspicious outbound connection events.

    When *count* ≥ 3, events simulate a beaconing pattern: intervals between
    successive connections cluster tightly around 60 s (jitter ≤ ±5 s),
    producing a coefficient of variation well below 0.3.

    Parameters
    ----------
    count:
        Number of events to generate.

    Returns
    -------
    List[Dict[str, Any]]
    """
    events: List[Dict[str, Any]] = []

    # Beaconing simulation – share one src/dst pair and use ~60 s intervals.
    beacon_src = random.choice(_INTERNAL_SRC_IPS)
    beacon_dst = random.choice(_C2_IPS)
    beacon_port = random.choice(_UNUSUAL_PORTS)
    base_time = datetime.now(timezone.utc)
    beacon_count = 0  # Counts only beacon events so their intervals stay ~60 s

    for i in range(count):
        is_beacon = count >= 3 and random.random() < 0.7

        if is_beacon:
            src_ip = beacon_src
            dst_ip = beacon_dst
            dst_port = beacon_port
            # ~60 s interval with ±3 s jitter; use beacon_count (not i) so that
            # intervals between successive beacon events are always ~60 s
            # regardless of how many non-beacon events were interleaved.
            jitter = random.uniform(-3, 3)
            ts = base_time + timedelta(seconds=(beacon_count * 60 + jitter))
            beacon_count += 1
        else:
            src_ip = random.choice(_INTERNAL_SRC_IPS)
            dst_ip = random.choice(_C2_IPS)
            dst_port = random.choice(_UNUSUAL_PORTS)
            ts = datetime.now(timezone.utc)

        event: Dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "timestamp": ts.isoformat(timespec="seconds"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "src_port": random.randint(49152, 65535),
            "protocol": random.choice(_PROTOCOLS),
            "bytes_sent": random.randint(200, 1024),
            "bytes_recv": random.randint(512, 4096),
            "duration_ms": random.randint(80, 500),
            "event_type": "suspicious_outbound",
            "severity": "high" if dst_port in [4444, 1337, 31337] else "medium",
            "is_beacon": is_beacon,
            "c2_domain": random.choice(_C2_DOMAINS) if random.random() < 0.4 else None,
        }
        events.append(event)

    return events


def generate_dns_query(count: int = 1) -> List[Dict[str, Any]]:
    """Generate *count* suspicious DNS query events.

    Alternates between DGA-style random hostnames and long-subdomain
    DNS-tunnelling queries.

    Parameters
    ----------
    count:
        Number of events to generate.

    Returns
    -------
    List[Dict[str, Any]]
    """
    events: List[Dict[str, Any]] = []
    for _ in range(count):
        use_dga = random.random() < 0.5
        query = _dga_domain() if use_dga else _long_subdomain()
        event: Dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "timestamp": _now_iso(),
            "src_ip": random.choice(_INTERNAL_SRC_IPS),
            "query": query,
            "query_type": random.choice(["A", "AAAA", "TXT", "MX"]),
            "response_code": random.choice(["NXDOMAIN", "NOERROR"]),
            "response_ip": random.choice(_C2_IPS) if random.random() < 0.5 else None,
            "bytes": random.randint(64, 512),
            "event_type": "suspicious_dns",
            "severity": "medium",
            "is_dga": use_dga,
            "is_tunnel": not use_dga,
        }
        events.append(event)
    return events
