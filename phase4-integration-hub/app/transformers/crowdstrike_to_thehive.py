"""Transform CrowdStrike Falcon detections into TheHive alerts.

Design notes
------------
* Severity mapping follows TheHive's 4-tier scale vs CrowdStrike's 1-100 integer score.
  The bands (1-25 / 26-50 / 51-74 / 75-100) align loosely with CrowdStrike's own
  Low / Medium / High / Critical display names so the mapping stays intuitive for analysts.

* Artifacts are extracted from every behavior in the detection rather than only the
  top-level fields.  This preserves forensic richness that would otherwise be lost.

* The raw CrowdStrike JSON is serialized into customFields.crowdstrike_raw so that
  analysts can access the original payload from TheHive without needing to query
  CrowdStrike separately.
"""

from __future__ import annotations

import json
from typing import List

from app.models.crowdstrike import CrowdStrikeDetection
from app.models.thehive import TheHiveAlert, TheHiveArtifact
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

def _map_severity(cs_severity: int) -> int:
    """Map CrowdStrike 1-100 severity to TheHive 1-4 severity.

    CrowdStrike uses a continuous numeric scale; TheHive uses four named tiers.
    The thresholds match the quartile boundaries of CrowdStrike's own naming:
      1-25  → Low (1)
      26-50 → Medium (2)
      51-74 → High (3)
      75-100 → Critical (4)
    """
    if cs_severity <= 25:
        return 1
    if cs_severity <= 50:
        return 2
    if cs_severity <= 74:
        return 3
    return 4


# ---------------------------------------------------------------------------
# Artifact extraction
# ---------------------------------------------------------------------------

def _extract_artifacts(detection: CrowdStrikeDetection) -> List[TheHiveArtifact]:
    """Convert detection behaviors into typed TheHive observables.

    We iterate every behavior so that a multi-stage attack chain produces a
    complete observable set.  Duplicates are deduplicated by (dataType, data).
    """
    seen: set[tuple[str, str]] = set()
    artifacts: List[TheHiveArtifact] = []

    def _add(data_type: str, data: str, message: str | None = None) -> None:
        key = (data_type, data)
        if data and key not in seen:
            seen.add(key)
            artifacts.append(TheHiveArtifact(dataType=data_type, data=data, message=message))

    for behavior in detection.behaviors:
        # File hashes – stored as "hash" type so TheHive can correlate across cases
        if behavior.sha256:
            _add("hash", behavior.sha256, f"SHA-256 from behavior {behavior.behavior_id}")
        if behavior.md5:
            _add("hash", behavior.md5, f"MD5 from behavior {behavior.behavior_id}")
        # Filename gives analysts quick context without opening the full case
        if behavior.filename:
            _add("filename", behavior.filename, f"From behavior {behavior.behavior_id}")
        # Parent process path can reveal living-off-the-land or loader techniques
        if behavior.filepath:
            _add("filename", behavior.filepath, f"Filepath from behavior {behavior.behavior_id}")

    # Device IP addresses – useful for network-level threat hunting and blocking
    if detection.device:
        if detection.device.local_ip:
            _add("ip", detection.device.local_ip, "Endpoint local IP")
        if detection.device.external_ip:
            _add("ip", detection.device.external_ip, "Endpoint external IP")

    # Top-level hashes (may differ from behavior hashes in multi-indicator detections)
    if detection.sha256:
        _add("hash", detection.sha256, "Top-level detection SHA-256")
    if detection.md5:
        _add("hash", detection.md5, "Top-level detection MD5")

    return artifacts


# ---------------------------------------------------------------------------
# Description builder
# ---------------------------------------------------------------------------

def _build_description(detection: CrowdStrikeDetection) -> str:
    """Compose a Markdown description that surfaces the most analyst-relevant fields."""
    device = detection.device
    hostname = device.hostname if device else "Unknown"
    local_ip = device.local_ip if device else "Unknown"
    external_ip = device.external_ip if device else "Unknown"
    os_version = device.os_version if device else "Unknown"

    behavior_lines = []
    for b in detection.behaviors:
        behavior_lines.append(
            f"- **{b.behavior_id}**: {b.tactic}/{b.technique} – {b.description or 'N/A'}"
        )
    behaviors_md = "\n".join(behavior_lines) if behavior_lines else "_(none)_"

    return (
        f"## CrowdStrike Detection: {detection.detection_id}\n\n"
        f"**Severity**: {detection.max_severity} ({detection.max_severity_displayname})\n"
        f"**Status**: {detection.status}\n\n"
        f"### Affected Host\n"
        f"- **Hostname**: {hostname}\n"
        f"- **Local IP**: {local_ip}\n"
        f"- **External IP**: {external_ip}\n"
        f"- **OS**: {os_version}\n\n"
        f"### Behaviors\n{behaviors_md}\n"
    )


# ---------------------------------------------------------------------------
# Public transformation functions
# ---------------------------------------------------------------------------

def transform_detection_to_alert(detection: CrowdStrikeDetection) -> TheHiveAlert:
    """Convert a single CrowdStrike detection to a TheHive alert.

    Logs the before/after JSON for every transformation so that data-fidelity
    issues can be diagnosed from logs alone, without needing live system access.
    """
    before_json = detection.model_dump_json()

    thehive_severity = _map_severity(detection.max_severity)
    tags: List[str] = ["crowdstrike"]
    if detection.tactic:
        tags.append(f"tactic:{detection.tactic}")
    if detection.technique:
        tags.append(f"technique:{detection.technique}")
    for behavior in detection.behaviors:
        if behavior.tactic:
            tags.append(f"tactic:{behavior.tactic}")
        if behavior.technique:
            tags.append(f"technique:{behavior.technique}")
    # Deduplicate while preserving insertion order
    tags = list(dict.fromkeys(tags))

    alert = TheHiveAlert(
        title=f"CrowdStrike Detection: {detection.detection_id}",
        description=_build_description(detection),
        severity=thehive_severity,
        # "CrowdStrike" as source lets TheHive operators filter/route by origin system
        source="CrowdStrike",
        # sourceRef carries the original detection_id so we can correlate back to Falcon
        sourceRef=detection.detection_id,
        type="alert",
        tags=tags,
        tlp=2,  # AMBER by default – detections may contain sensitive endpoint data
        pap=2,
        customFields={
            # Preserve raw payload so analysts can access every CrowdStrike field
            # without leaving TheHive or querying the Falcon console
            "crowdstrike_raw": detection.model_dump(),
        },
        artifacts=_extract_artifacts(detection),
    )

    after_json = alert.model_dump_json()
    logger.info(
        "transformed_detection_to_alert",
        detection_id=detection.detection_id,
        cs_severity=detection.max_severity,
        thehive_severity=thehive_severity,
        artifact_count=len(alert.artifacts),
        before=before_json,
        after=after_json,
    )
    return alert


def transform_detections_batch(detections: list) -> List[TheHiveAlert]:
    """Transform a list of CrowdStrike detections to TheHive alerts."""
    alerts = []
    for detection in detections:
        if not isinstance(detection, CrowdStrikeDetection):
            detection = CrowdStrikeDetection(**detection)
        alerts.append(transform_detection_to_alert(detection))
    return alerts
