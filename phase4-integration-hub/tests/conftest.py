"""Pytest fixtures shared across the test suite."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.crowdstrike import (
    CrowdStrikeBehavior,
    CrowdStrikeDetection,
    CrowdStrikeDevice,
)
from app.models.thehive import SyncStatus
from app.services.sync_manager import SyncManager


# ---------------------------------------------------------------------------
# Mock service factories
# ---------------------------------------------------------------------------


def _make_mock_crowdstrike():
    svc = AsyncMock()
    svc.circuit_breaker_state = "CLOSED"
    from mocks.crowdstrike_responses import get_mock_detections
    from app.models.crowdstrike import CrowdStrikeDetection

    svc.get_detections.return_value = [
        CrowdStrikeDetection(**d) for d in get_mock_detections()
    ]
    svc.update_detection.return_value = True
    return svc


def _make_mock_thehive():
    svc = AsyncMock()
    svc.circuit_breaker_state = "CLOSED"
    svc.create_alert.return_value = {"_id": "mock-alert-id"}
    svc.create_case.return_value = {"_id": "mock-case-id"}
    svc.update_case.return_value = {"_id": "mock-case-id"}
    return svc


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def mock_crowdstrike_service():
    return _make_mock_crowdstrike()


@pytest.fixture(scope="session")
def mock_thehive_service():
    return _make_mock_thehive()


@pytest.fixture()
def app_client():
    """TestClient with mocked downstream services injected into app state."""
    cs_svc = _make_mock_crowdstrike()
    hive_svc = _make_mock_thehive()

    manager = SyncManager(crowdstrike=cs_svc, thehive=hive_svc)

    # Inject manager directly into app state to bypass lifespan startup
    app.state.sync_manager = manager

    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


@pytest.fixture()
def sample_crowdstrike_detection() -> CrowdStrikeDetection:
    return CrowdStrikeDetection(
        detection_id="ldt:abc123def456abc123def456abc12301:9876543210",
        cid="abc123def456abc123def456abc12301",
        created_timestamp="2024-01-15T08:32:11.000Z",
        max_severity=80,
        max_severity_displayname="Critical",
        status="new",
        tactic="Execution",
        technique="PowerShell",
        behaviors=[
            CrowdStrikeBehavior(
                behavior_id="behav001",
                tactic="Execution",
                technique="PowerShell",
                severity=80,
                confidence=90,
                description="Encoded PowerShell command",
                filename="powershell.exe",
                filepath="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                cmdline="powershell.exe -EncodedCommand abc",
                sha256="a" * 64,
                md5="a" * 32,
            )
        ],
        device=CrowdStrikeDevice(
            device_id="dev001",
            hostname="WORKSTATION-042",
            local_ip="10.10.5.42",
            external_ip="203.0.113.42",
            os_version="Windows 10 Enterprise",
            platform_name="Windows",
        ),
        sha256="a" * 64,
        md5="a" * 32,
    )


@pytest.fixture()
def sample_thehive_webhook() -> dict:
    return {
        "operation": "Update",
        "objectType": "Case",
        "objectId": "~12345",
        "object": {
            "sourceRef": "ldt:abc123def456abc123def456abc12301:9876543210",
            "status": "Resolved",
            "summary": "False positive confirmed by analyst",
            "customFields": {},
        },
    }
