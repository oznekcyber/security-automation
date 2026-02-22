"""IOC (Indicator of Compromise) file-hash detection event generator.

Simulates AV/EDR telemetry where on-disk files match known malware hashes.
Hashes are realistic-looking but fictitious (except for the EICAR test string
hash, which is a publicly documented test artifact with no malicious payload).
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

_HOSTNAMES: List[str] = [
    "WORKSTATION-01", "WORKSTATION-42", "LAPTOP-JSMITH",
    "SERVER-APP01", "SERVER-DB02", "KIOSK-LOBBY",
]

_USERNAMES: List[str] = [
    "jsmith", "bwilliams", "adm_jones", "SYSTEM",
    "svc_deploy", "Administrator",
]

# Known malware reference hashes (MD5 / SHA-256).
# EICAR is the standard AV test file – included here to exercise the "clean
# test artefact" path in CI pipelines.
_KNOWN_MALWARE: List[Dict[str, Any]] = [
    {
        "md5": "44d88612fea8a8f36de82e1278abb02f",
        "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "threat_name": "EICAR-Test-File",
        "threat_family": "test",
        "detection_engine": "EICAR",
        "severity": "low",
    },
    {
        "md5": "a2fb219e40b1e1b2831dd6e8d7db17fd",
        "sha256": "2f1f52c7e3a59b3b81b27e93e2e73c89dab6204e3e5b72af91b2aad2a8cf1abe",
        "threat_name": "Mimikatz",
        "threat_family": "credential_dumper",
        "detection_engine": "CrowdStrike",
        "severity": "critical",
    },
    {
        "md5": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "threat_name": "Cobalt Strike Beacon",
        "threat_family": "rat",
        "detection_engine": "SentinelOne",
        "severity": "critical",
    },
    {
        "md5": "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
        "sha256": "a87ff679a2f3e71d9181a67b7542122c5c3e24b4bcef17b1ce1e3a7df0e2c8f9",
        "threat_name": "Empire Stager",
        "threat_family": "post_exploitation",
        "detection_engine": "Carbon Black",
        "severity": "critical",
    },
    {
        "md5": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
        "sha256": "b14a7b8059d9c055954c92674ce60032d5f6b7c2b77aa1b5a891d5b8c3d3f4a5",
        "threat_name": "Metasploit Meterpreter",
        "threat_family": "rat",
        "detection_engine": "Defender ATP",
        "severity": "critical",
    },
    {
        "md5": "f1e2d3c4b5a6978869504132435f6a7b",
        "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "threat_name": "Ryuk Ransomware Dropper",
        "threat_family": "ransomware",
        "detection_engine": "Sophos",
        "severity": "critical",
    },
    {
        "md5": "a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4",
        "sha256": "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a",
        "threat_name": "Emotet Loader",
        "threat_family": "trojan",
        "detection_engine": "ESET",
        "severity": "high",
    },
]

_FILE_PATHS_WINDOWS: List[str] = [
    "C:\\Users\\Public\\Downloads\\",
    "C:\\Windows\\Temp\\",
    "C:\\Temp\\",
    "C:\\ProgramData\\",
    "C:\\Users\\{user}\\AppData\\Local\\Temp\\",
    "C:\\Users\\{user}\\Desktop\\",
]

_FILE_EXTENSIONS: List[str] = [".exe", ".dll", ".ps1", ".bat", ".vbs"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _random_file_path(username: str) -> tuple[str, str]:
    """Return a (full_path, file_name) tuple."""
    base_dir = random.choice(_FILE_PATHS_WINDOWS).replace("{user}", username)
    stem = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=8))
    ext = random.choice(_FILE_EXTENSIONS)
    name = stem + ext
    return base_dir + name, name


def generate_ioc_match(count: int = 1) -> List[Dict[str, Any]]:
    """Generate *count* file-hash IOC match events.

    Each event represents an AV/EDR engine detecting a known malicious file on
    an endpoint.

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
        malware = random.choice(_KNOWN_MALWARE)
        username = random.choice(_USERNAMES)
        file_path, file_name = _random_file_path(username)

        # Simulate file creation time a few hours before detection.
        created_delta = timedelta(hours=random.uniform(0.5, 72))
        creation_time = (datetime.now(timezone.utc) - created_delta).isoformat(
            timespec="seconds"
        )

        event: Dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "timestamp": _now_iso(),
            "hostname": random.choice(_HOSTNAMES),
            "username": username,
            "file_path": file_path,
            "file_name": file_name,
            "md5": malware["md5"],
            "sha256": malware["sha256"],
            "threat_name": malware["threat_name"],
            "threat_family": malware["threat_family"],
            "detection_engine": malware["detection_engine"],
            "severity": malware["severity"],
            "event_type": "ioc_file_match",
            "file_size_bytes": random.randint(4096, 10_485_760),
            "file_creation_time": creation_time,
            "action_taken": random.choice(["quarantined", "blocked", "detected_only"]),
        }
        events.append(event)
    return events
