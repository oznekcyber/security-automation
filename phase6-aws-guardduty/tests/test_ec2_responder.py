"""
Tests for the EC2 GuardDuty responder Lambda handler.

All tests use moto to mock AWS API calls — no real AWS credentials needed.
Run with: pytest tests/test_ec2_responder.py -v
"""

from __future__ import annotations

import json
import os
import sys

import boto3
import pytest
from moto import mock_aws

# Make the lambda handler importable via importlib to avoid sys.path collisions
import importlib.util

# Patch out shared modules before importing handler
import unittest.mock as mock
sys.modules.setdefault("shared", mock.MagicMock())
sys.modules.setdefault("shared.thehive_client", mock.MagicMock())
sys.modules.setdefault("shared.splunk_client", mock.MagicMock())
sys.modules.setdefault("shared.slack_notifier", mock.MagicMock())

_ec2_handler_path = os.path.join(
    os.path.dirname(__file__), "..", "lambda", "ec2_responder", "handler.py"
)
_spec = importlib.util.spec_from_file_location("ec2_handler_module", _ec2_handler_path)
_ec2_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ec2_module)

isolate_instance = _ec2_module.isolate_instance
snapshot_volumes = _ec2_module.snapshot_volumes
tag_instance = _ec2_module.tag_instance
ec2_handler = _ec2_module.handler


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    """Set dummy AWS credentials so moto doesn't try to use real credentials."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("QUARANTINE_SG_NAME", "guardduty-quarantine")


@pytest.fixture(autouse=True)
def aws_mock():
    """Start moto mock context for all tests."""
    with mock_aws():
        yield

@pytest.fixture
def ec2_client():
    return boto3.client("ec2", region_name="us-east-1")


@pytest.fixture
def mock_ec2_infrastructure(ec2_client):
    """
    Create a minimal mocked EC2 environment:
    - Default VPC (provided by moto)
    - Quarantine security group
    - Normal security group
    - One running EC2 instance with one EBS volume attached
    """
    # Get default VPC
    vpcs = ec2_client.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
    vpc_id = vpcs["Vpcs"][0]["VpcId"]

    # Create quarantine SG
    quarantine_sg = ec2_client.create_security_group(
        GroupName="guardduty-quarantine",
        Description="GuardDuty quarantine deny-all",
        VpcId=vpc_id,
    )
    quarantine_sg_id = quarantine_sg["GroupId"]

    # Revoke all outbound rules (deny-all)
    ec2_client.revoke_security_group_egress(
        GroupId=quarantine_sg_id,
        IpPermissions=[
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ],
    )

    # Create normal web SG
    web_sg = ec2_client.create_security_group(
        GroupName="web-sg",
        Description="Normal web security group",
        VpcId=vpc_id,
    )
    web_sg_id = web_sg["GroupId"]

    # Launch an instance
    instance_resp = ec2_client.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.medium",
        SecurityGroupIds=[web_sg_id],
    )
    instance_id = instance_resp["Instances"][0]["InstanceId"]

    return {
        "vpc_id": vpc_id,
        "quarantine_sg_id": quarantine_sg_id,
        "web_sg_id": web_sg_id,
        "instance_id": instance_id,
    }


def _make_finding(instance_id: str, severity: float = 8.0) -> dict:
    """Build a minimal EC2 GuardDuty finding for testing."""
    return {
        "id": "test-finding-001",
        "type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "severity": severity,
        "region": "us-east-1",
        "accountId": "123456789012",
        "description": "Test finding",
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId": instance_id,
            },
        },
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_isolate_instance_replaces_security_groups(mock_ec2_infrastructure, ec2_client):
    """Isolating an instance should replace all its SGs with the quarantine SG."""
    instance_id = mock_ec2_infrastructure["instance_id"]
    quarantine_sg_id = mock_ec2_infrastructure["quarantine_sg_id"]

    original_sgs = isolate_instance(ec2_client, instance_id, quarantine_sg_id)

    # Verify the instance now has only the quarantine SG
    resp = ec2_client.describe_instances(InstanceIds=[instance_id])
    current_sgs = [sg["GroupId"] for sg in resp["Reservations"][0]["Instances"][0]["SecurityGroups"]]
    assert current_sgs == [quarantine_sg_id], f"Expected quarantine SG only, got {current_sgs}"

    # Verify original SGs were returned
    assert isinstance(original_sgs, list)
    assert len(original_sgs) >= 1



def test_snapshot_volumes_creates_snapshots(mock_ec2_infrastructure, ec2_client):
    """snapshot_volumes should create one EBS snapshot per attached volume."""
    instance_id = mock_ec2_infrastructure["instance_id"]
    finding_id = "test-finding-001"

    snapshot_ids = snapshot_volumes(ec2_client, instance_id, finding_id)

    assert isinstance(snapshot_ids, list)
    assert len(snapshot_ids) >= 1

    # Verify snapshot exists
    snap_resp = ec2_client.describe_snapshots(SnapshotIds=snapshot_ids)
    assert len(snap_resp["Snapshots"]) == len(snapshot_ids)

    # Verify forensic tags
    snap = snap_resp["Snapshots"][0]
    tags = {t["Key"]: t["Value"] for t in snap.get("Tags", [])}
    assert tags.get("Purpose") == "forensic"
    assert tags.get("GuardDutyFindingId") == finding_id



def test_tag_instance_applies_metadata(mock_ec2_infrastructure, ec2_client):
    """tag_instance should apply security metadata tags to the instance."""
    instance_id = mock_ec2_infrastructure["instance_id"]
    finding = _make_finding(instance_id)

    tag_instance(ec2_client, instance_id, finding, ["snap-12345678"], ["sg-original"])

    resp = ec2_client.describe_instances(InstanceIds=[instance_id])
    tags = {t["Key"]: t["Value"] for t in resp["Reservations"][0]["Instances"][0].get("Tags", [])}

    assert tags.get("SecurityStatus") == "QUARANTINED"
    assert tags.get("GuardDutyFindingId") == "test-finding-001"
    assert "QuarantinedAt" in tags
    assert tags.get("ForensicSnapshots") == "snap-12345678"



def test_handler_end_to_end_success(mock_ec2_infrastructure, monkeypatch):
    """Full handler invocation should isolate, snapshot, and tag the instance."""
    instance_id = mock_ec2_infrastructure["instance_id"]
    quarantine_sg_id = mock_ec2_infrastructure["quarantine_sg_id"]
    monkeypatch.setenv("QUARANTINE_SG_NAME", "guardduty-quarantine")

    finding = _make_finding(instance_id)
    event = {"detail": finding}

    result = ec2_handler(event, None)

    assert result["status"] == "success"
    assert result["instance_id"] == instance_id
    assert len(result["automated_actions"]) >= 3  # isolate, snapshot, tag

    # Verify containment: instance should now have quarantine SG
    ec2 = boto3.client("ec2", region_name="us-east-1")
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    current_sgs = [sg["GroupId"] for sg in resp["Reservations"][0]["Instances"][0]["SecurityGroups"]]
    assert quarantine_sg_id in current_sgs



def test_handler_missing_instance_id():
    """Handler should return error if no instance ID in finding."""
    finding = {
        "id": "test-finding-no-instance",
        "type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "severity": 8.0,
        "region": "us-east-1",
        "accountId": "123456789012",
        "resource": {"resourceType": "Instance", "instanceDetails": {}},
    }
    result = ec2_handler({"detail": finding}, None)
    assert result["status"] == "error"
    assert result["reason"] == "no_instance_id"



def test_handler_quarantine_sg_not_found(monkeypatch):
    """Handler should return error if quarantine SG doesn't exist."""
    monkeypatch.setenv("QUARANTINE_SG_NAME", "nonexistent-sg")

    finding = {
        "id": "test-finding-no-sg",
        "type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "severity": 8.0,
        "region": "us-east-1",
        "accountId": "123456789012",
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {"instanceId": "i-nonexistent"},
        },
    }
    result = ec2_handler({"detail": finding}, None)
    assert result["status"] == "error"
