"""Tests for webhook and health endpoints."""

from __future__ import annotations

import pytest


class TestTheHiveWebhook:
    def test_valid_payload_returns_202(self, app_client):
        payload = {
            "operation": "Update",
            "objectType": "Case",
            "objectId": "~12345",
            "object": {
                "sourceRef": "ldt:abc123def456abc123def456abc12301:9876543210",
                "status": "Resolved",
                "summary": "Confirmed malicious",
                "customFields": {},
            },
        }
        resp = app_client.post("/api/v1/webhooks/thehive", json=payload)
        assert resp.status_code == 202
        assert resp.json()["accepted"] is True

    def test_invalid_payload_returns_422(self, app_client):
        # Pass a list where an object is expected
        resp = app_client.post("/api/v1/webhooks/thehive", json="not-an-object")
        assert resp.status_code == 422

    def test_empty_payload_still_accepted(self, app_client):
        # TheHiveWebhookPayload has all Optional fields — empty dict is valid
        resp = app_client.post("/api/v1/webhooks/thehive", json={})
        assert resp.status_code == 202


class TestCrowdStrikeWebhook:
    def _valid_payload(self):
        return {
            "event_type": "DetectionSummaryEvent",
            "detection": {
                "detection_id": "ldt:abc123def456abc123def456abc12301:9876543210",
                "cid": "abc123def456abc123def456abc12301",
                "max_severity": 80,
                "max_severity_displayname": "Critical",
                "status": "new",
                "behaviors": [
                    {
                        "behavior_id": "behav001",
                        "tactic": "Execution",
                        "technique": "PowerShell",
                        "severity": 80,
                        "confidence": 90,
                        "sha256": "a" * 64,
                        "md5": "a" * 32,
                        "filename": "powershell.exe",
                    }
                ],
                "device": {
                    "device_id": "dev001",
                    "hostname": "WORKSTATION-042",
                    "local_ip": "10.10.5.42",
                },
            },
        }

    def test_valid_payload_returns_202(self, app_client):
        resp = app_client.post("/api/v1/webhooks/crowdstrike", json=self._valid_payload())
        assert resp.status_code == 202
        assert resp.json()["accepted"] is True

    def test_invalid_payload_returns_422(self, app_client):
        resp = app_client.post("/api/v1/webhooks/crowdstrike", json="not-an-object")
        assert resp.status_code == 422

    def test_payload_without_detection_accepted(self, app_client):
        # event_type only — detection field is Optional
        resp = app_client.post(
            "/api/v1/webhooks/crowdstrike",
            json={"event_type": "AuthActivityAuditEvent"},
        )
        assert resp.status_code == 202


class TestHealthEndpoint:
    def test_health_returns_200(self, app_client):
        resp = app_client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_health_structure(self, app_client):
        data = app_client.get("/api/v1/health").json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "services" in data
        assert "crowdstrike" in data["services"]
        assert "thehive" in data["services"]

    def test_health_circuit_breaker_field(self, app_client):
        data = app_client.get("/api/v1/health").json()
        assert "circuit_breaker" in data["services"]["crowdstrike"]
        assert "circuit_breaker" in data["services"]["thehive"]
