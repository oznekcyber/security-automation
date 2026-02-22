"""Tests for the CrowdStrike ↔ TheHive transformer functions."""

from __future__ import annotations

import pytest

from app.models.crowdstrike import CrowdStrikeBehavior, CrowdStrikeDetection, CrowdStrikeDevice
from app.models.thehive import TheHiveWebhookPayload
from app.transformers.crowdstrike_to_thehive import (
    _map_severity,
    transform_detection_to_alert,
)
from app.transformers.thehive_to_crowdstrike import (
    extract_detection_id,
    transform_case_update_to_crowdstrike,
)


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

class TestSeverityMapping:
    def test_critical_severity_80(self):
        assert _map_severity(80) == 4

    def test_critical_boundary_75(self):
        assert _map_severity(75) == 4

    def test_high_severity_55(self):
        assert _map_severity(55) == 3

    def test_high_boundary_51(self):
        assert _map_severity(51) == 3

    def test_high_boundary_74(self):
        assert _map_severity(74) == 3

    def test_medium_severity_30(self):
        assert _map_severity(30) == 2

    def test_medium_boundary_26(self):
        assert _map_severity(26) == 2

    def test_medium_boundary_50(self):
        assert _map_severity(50) == 2

    def test_low_severity_10(self):
        assert _map_severity(10) == 1

    def test_low_boundary_25(self):
        assert _map_severity(25) == 1

    def test_low_boundary_1(self):
        assert _map_severity(1) == 1

    def test_max_severity_100(self):
        assert _map_severity(100) == 4


# ---------------------------------------------------------------------------
# Detection → Alert transformation
# ---------------------------------------------------------------------------

class TestTransformDetectionToAlert:
    def _make_detection(self, severity=80, behaviors=None, device=None) -> CrowdStrikeDetection:
        if behaviors is None:
            behaviors = [
                CrowdStrikeBehavior(
                    behavior_id="b1",
                    tactic="Execution",
                    technique="PowerShell",
                    severity=severity,
                    sha256="a" * 64,
                    md5="b" * 32,
                    filename="powershell.exe",
                    filepath="C:\\Windows\\powershell.exe",
                )
            ]
        if device is None:
            device = CrowdStrikeDevice(
                device_id="dev1",
                hostname="HOST-01",
                local_ip="10.0.0.1",
                external_ip="1.2.3.4",
            )
        return CrowdStrikeDetection(
            detection_id="ldt:test:001",
            max_severity=severity,
            max_severity_displayname="Critical",
            status="new",
            tactic="Execution",
            technique="PowerShell",
            behaviors=behaviors,
            device=device,
        )

    def test_severity_mapping_applied(self):
        alert = transform_detection_to_alert(self._make_detection(severity=80))
        assert alert.severity == 4

    def test_severity_55_maps_to_high(self):
        alert = transform_detection_to_alert(self._make_detection(severity=55))
        assert alert.severity == 3

    def test_severity_30_maps_to_medium(self):
        alert = transform_detection_to_alert(self._make_detection(severity=30))
        assert alert.severity == 2

    def test_severity_10_maps_to_low(self):
        alert = transform_detection_to_alert(self._make_detection(severity=10))
        assert alert.severity == 1

    def test_file_hash_artifacts_extracted(self):
        alert = transform_detection_to_alert(self._make_detection())
        hash_artifacts = [a for a in alert.artifacts if a.dataType == "hash"]
        assert len(hash_artifacts) >= 1
        sha_values = [a.data for a in hash_artifacts]
        assert "a" * 64 in sha_values

    def test_ip_artifacts_extracted(self):
        alert = transform_detection_to_alert(self._make_detection())
        ip_artifacts = [a for a in alert.artifacts if a.dataType == "ip"]
        ip_values = [a.data for a in ip_artifacts]
        assert "10.0.0.1" in ip_values

    def test_filename_artifact_extracted(self):
        alert = transform_detection_to_alert(self._make_detection())
        fn_artifacts = [a for a in alert.artifacts if a.dataType == "filename"]
        assert any("powershell.exe" in a.data for a in fn_artifacts)

    def test_device_info_in_description(self):
        alert = transform_detection_to_alert(self._make_detection())
        assert "HOST-01" in alert.description
        assert "10.0.0.1" in alert.description

    def test_source_is_crowdstrike(self):
        alert = transform_detection_to_alert(self._make_detection())
        assert alert.source == "CrowdStrike"

    def test_source_ref_is_detection_id(self):
        alert = transform_detection_to_alert(self._make_detection())
        assert alert.sourceRef == "ldt:test:001"

    def test_raw_payload_in_custom_fields(self):
        alert = transform_detection_to_alert(self._make_detection())
        assert "crowdstrike_raw" in alert.customFields
        raw = alert.customFields["crowdstrike_raw"]
        assert raw["detection_id"] == "ldt:test:001"

    def test_tactic_tag_added(self):
        alert = transform_detection_to_alert(self._make_detection())
        assert "tactic:Execution" in alert.tags

    def test_technique_tag_added(self):
        alert = transform_detection_to_alert(self._make_detection())
        assert "technique:PowerShell" in alert.tags


# ---------------------------------------------------------------------------
# TheHive → CrowdStrike transformer
# ---------------------------------------------------------------------------

class TestTransformCaseUpdateToCrowdstrike:
    def _make_payload(self, status="Resolved", source_ref="ldt:test:001") -> TheHiveWebhookPayload:
        return TheHiveWebhookPayload(
            operation="Update",
            objectType="Case",
            objectId="~123",
            object={
                "sourceRef": source_ref,
                "status": status,
                "summary": "Analyst resolved",
            },
        )

    def test_resolved_maps_to_closed(self):
        result = transform_case_update_to_crowdstrike(self._make_payload(status="Resolved"))
        assert result["status"] == "closed"

    def test_in_progress_maps_to_in_progress(self):
        result = transform_case_update_to_crowdstrike(self._make_payload(status="In Progress"))
        assert result["status"] == "in_progress"

    def test_new_maps_to_new(self):
        result = transform_case_update_to_crowdstrike(self._make_payload(status="New"))
        assert result["status"] == "new"

    def test_detection_id_extracted(self):
        result = transform_case_update_to_crowdstrike(self._make_payload())
        assert result["detection_id"] == "ldt:test:001"

    def test_no_detection_id_returns_empty(self):
        payload = TheHiveWebhookPayload(
            operation="Update",
            objectType="Case",
            objectId="~999",
            object={"status": "Resolved", "sourceRef": "MANUAL-001"},
        )
        result = transform_case_update_to_crowdstrike(payload)
        # sourceRef doesn't start with "ldt:" → no match
        assert result == {}

    def test_comment_included(self):
        result = transform_case_update_to_crowdstrike(self._make_payload())
        assert "comment" in result
        assert result["comment"] == "Analyst resolved"


class TestExtractDetectionId:
    def test_extract_from_source_ref(self):
        case = {"sourceRef": "ldt:abc:001"}
        assert extract_detection_id(case) == "ldt:abc:001"

    def test_extract_from_custom_fields_raw(self):
        case = {
            "sourceRef": "MANUAL",
            "customFields": {"crowdstrike_raw": {"detection_id": "ldt:xyz:999"}},
        }
        assert extract_detection_id(case) == "ldt:xyz:999"

    def test_extract_from_custom_fields_direct(self):
        case = {
            "customFields": {"crowdstrike_detection_id": "ldt:direct:001"},
        }
        assert extract_detection_id(case) == "ldt:direct:001"

    def test_returns_none_when_not_found(self):
        assert extract_detection_id({}) is None
