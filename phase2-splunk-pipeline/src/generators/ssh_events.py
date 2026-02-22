"""SSH security event generator.

Produces realistic mock SSH authentication events in both CEF and JSON
formats.  Events are designed to model real-world attack patterns such as
brute-force credential stuffing and stolen-key abuse.

CEF format reference:
    CEF:0|<vendor>|<product>|<version>|<event_id>|<name>|<severity>|<extensions>
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

# ── realistic attacker IP pool ────────────────────────────────────────────────
# Mix of Tor exit nodes, known scanner ranges, and cloud-provider VMs.
_ATTACKER_IPS: List[str] = [
    "185.220.101.34",   # Tor exit
    "185.220.101.35",   # Tor exit
    "185.220.101.48",   # Tor exit
    "195.206.105.217",  # known scanner
    "45.33.32.156",     # Shodan scanner
    "80.82.77.33",      # Shodan scanner
    "94.102.49.190",    # scanner
    "198.20.69.74",     # Rapid7
    "71.6.135.131",     # Censys
    "89.248.167.131",   # Masscan
    "209.141.33.15",    # VPN/proxy
    "103.216.220.24",   # cloud VM
    "167.71.13.196",    # DigitalOcean
    "142.93.201.48",    # DigitalOcean
    "134.209.82.208",   # DigitalOcean
]

_HONEYPOT_HOSTS: List[str] = [
    "ssh-bastion-01", "jump-host-prod", "bastion-us-east-1",
    "linux-dev-01", "ubuntu-web-02", "db-server-03",
]

_USERNAMES: List[str] = [
    "admin", "root", "ubuntu", "oracle", "postgres",
    "pi", "test", "deploy", "git", "ec2-user",
    "ansible", "jenkins", "nagios", "hadoop",
]

_FAILURE_REASONS: List[str] = [
    "Invalid password",
    "Invalid user",
    "Connection refused",
    "Too many authentication failures",
    "Permission denied (publickey)",
    "Authentication failure",
]

_DST_IPS: List[str] = [
    "10.0.1.5", "10.0.1.12", "172.16.0.100", "192.168.1.200",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _epoch(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


def _cef_severity(severity: str) -> int:
    """Map severity label to CEF numeric severity (0–10)."""
    mapping = {"low": 3, "medium": 5, "high": 8, "critical": 10}
    return mapping.get(severity.lower(), 5)


def _build_ssh_cef(event: Dict[str, Any]) -> str:
    """Render a CEF format string for an SSH event."""
    sev_num = _cef_severity(event["severity"])
    ext = (
        f"src={event['src_ip']} dst={event['dst_ip']} "
        f"suser={event['username']} msg={event['failure_reason']} "
        f"cs1={event['source_host']} cs1Label=SourceHost "
        f"eventId={event['event_id']}"
    )
    return (
        f"CEF:0|OpenSSH|sshd|8.9|{event['event_type']}|"
        f"{event['event_name']}|{sev_num}|{ext}"
    )


def generate_ssh_failed_login(count: int = 1) -> List[Dict[str, Any]]:
    """Generate *count* SSH failed-login events.

    Includes a brute-force burst pattern: ~30 % of the time several events
    share the same source IP to model a credential-stuffing run.

    Parameters
    ----------
    count:
        Number of events to generate.

    Returns
    -------
    List[Dict[str, Any]]
        Each dict includes both a ``cef_raw`` string and all structured
        fields.
    """
    events: List[Dict[str, Any]] = []

    # Occasionally reuse a single attacker IP to model a brute-force burst.
    burst_ip = random.choice(_ATTACKER_IPS)
    use_burst = count >= 3

    for i in range(count):
        if use_burst and random.random() < 0.6:
            src_ip = burst_ip
        else:
            src_ip = random.choice(_ATTACKER_IPS)

        timestamp = _now_iso()
        severity = "high" if use_burst else random.choice(["medium", "high"])
        event: Dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": random.choice(_DST_IPS),
            "username": random.choice(_USERNAMES),
            "failure_reason": random.choice(_FAILURE_REASONS),
            "severity": severity,
            "source_host": random.choice(_HONEYPOT_HOSTS),
            "event_type": "ssh_failed_login",
            "event_name": "SSH Authentication Failure",
            "auth_method": random.choice(["password", "publickey", "keyboard-interactive"]),
            "port": 22,
        }
        event["cef_raw"] = _build_ssh_cef(event)
        events.append(event)

    return events


def generate_ssh_successful_login(count: int = 1) -> List[Dict[str, Any]]:
    """Generate *count* suspicious SSH successful-login events.

    Suspicious logins use attacker IPs or unusual usernames, suggesting
    credential compromise or stolen private keys.

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
        timestamp = _now_iso()
        event: Dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp,
            "src_ip": random.choice(_ATTACKER_IPS),
            "dst_ip": random.choice(_DST_IPS),
            "username": random.choice(["root", "admin", "oracle", "postgres"]),
            "failure_reason": "N/A",
            "severity": "critical",
            "source_host": random.choice(_HONEYPOT_HOSTS),
            "event_type": "ssh_successful_login",
            "event_name": "Suspicious SSH Successful Login",
            "auth_method": random.choice(["password", "publickey"]),
            "port": 22,
            "session_id": str(uuid.uuid4())[:8],
        }
        event["cef_raw"] = _build_ssh_cef(event)
        events.append(event)

    return events
