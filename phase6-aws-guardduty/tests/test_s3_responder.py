"""
Tests for the S3 GuardDuty responder Lambda handler.

All tests use moto to mock AWS API calls — no real AWS credentials needed.
Run with: pytest tests/test_s3_responder.py -v
"""

from __future__ import annotations

import json
import os
import sys
import unittest.mock as mock

import boto3
import pytest
from moto import mock_aws

# Make the lambda handler importable via importlib to avoid sys.path collisions
import importlib.util

sys.modules.setdefault("shared", mock.MagicMock())
sys.modules.setdefault("shared.thehive_client", mock.MagicMock())
sys.modules.setdefault("shared.splunk_client", mock.MagicMock())
sys.modules.setdefault("shared.slack_notifier", mock.MagicMock())

_s3_handler_path = os.path.join(
    os.path.dirname(__file__), "..", "lambda", "s3_responder", "handler.py"
)
_spec = importlib.util.spec_from_file_location("s3_handler_module", _s3_handler_path)
_s3_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_s3_module)

block_public_access = _s3_module.block_public_access
apply_restrictive_policy = _s3_module.apply_restrictive_policy
s3_handler = _s3_module.handler


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture(autouse=True)
def aws_mock():
    """Start moto mock context for all tests."""
    with mock_aws():
        yield


@pytest.fixture
def s3_client():
    return boto3.client("s3", region_name="us-east-1")


@pytest.fixture
def mock_s3_bucket(s3_client):
    """Create a test S3 bucket with public access enabled (simulating a GuardDuty finding scenario)."""
    bucket_name = "test-data-bucket-12345"
    s3_client.create_bucket(Bucket=bucket_name)
    # Disable block public access (simulating the condition GuardDuty detected)
    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    return bucket_name


def _make_s3_finding(bucket_name: str) -> dict:
    return {
        "id": "s3-finding-001",
        "type": "Policy:S3/BucketBlockPublicAccessDisabled",
        "severity": 8.0,
        "region": "us-east-1",
        "accountId": "123456789012",
        "description": "S3 Block Public Access was disabled",
        "resource": {
            "resourceType": "S3Bucket",
            "s3BucketDetails": [
                {
                    "arn": f"arn:aws:s3:::{bucket_name}",
                    "name": bucket_name,
                    "type": "Destination",
                }
            ],
        },
    }



def test_block_public_access_enables_all_settings(mock_s3_bucket, s3_client):
    """block_public_access should enable all four Block Public Access settings."""
    block_public_access(s3_client, mock_s3_bucket)

    config = s3_client.get_public_access_block(Bucket=mock_s3_bucket)
    block_config = config["PublicAccessBlockConfiguration"]

    assert block_config["BlockPublicAcls"] is True
    assert block_config["IgnorePublicAcls"] is True
    assert block_config["BlockPublicPolicy"] is True
    assert block_config["RestrictPublicBuckets"] is True



def test_apply_restrictive_policy(mock_s3_bucket, s3_client):
    """apply_restrictive_policy should set a deny-external policy on the bucket."""
    apply_restrictive_policy(s3_client, mock_s3_bucket, "123456789012")

    policy_resp = s3_client.get_bucket_policy(Bucket=mock_s3_bucket)
    policy = json.loads(policy_resp["Policy"])

    statements = {s["Sid"]: s for s in policy["Statement"]}
    assert "GuardDutyDenyExternalGetObject" in statements
    assert "GuardDutyDenyExternalPutObject" in statements

    get_stmt = statements["GuardDutyDenyExternalGetObject"]
    assert get_stmt["Effect"] == "Deny"
    assert get_stmt["Action"] == "s3:GetObject"



def test_handler_end_to_end_success(mock_s3_bucket):
    """Full handler should block public access and apply restrictive policy."""
    finding = _make_s3_finding(mock_s3_bucket)
    result = s3_handler({"detail": finding}, None)

    assert result["status"] == "success"
    assert result["bucket_name"] == mock_s3_bucket
    assert len(result["automated_actions"]) >= 2

    # Verify public access is now blocked
    s3 = boto3.client("s3", region_name="us-east-1")
    config = s3.get_public_access_block(Bucket=mock_s3_bucket)
    block_config = config["PublicAccessBlockConfiguration"]
    assert block_config["BlockPublicAcls"] is True
    assert block_config["BlockPublicPolicy"] is True



def test_handler_missing_bucket_name():
    """Handler should return error if no bucket name in finding."""
    finding = {
        "id": "s3-finding-no-bucket",
        "type": "Policy:S3/BucketBlockPublicAccessDisabled",
        "severity": 8.0,
        "region": "us-east-1",
        "accountId": "123456789012",
        "resource": {"resourceType": "S3Bucket", "s3BucketDetails": []},
    }
    result = s3_handler({"detail": finding}, None)
    assert result["status"] == "error"
    assert result["reason"] == "no_bucket_name"



def test_handler_direct_finding_no_envelope(mock_s3_bucket):
    """Handler should work even if called with raw finding (no EventBridge envelope)."""
    finding = _make_s3_finding(mock_s3_bucket)
    # Pass finding directly without EventBridge envelope
    result = s3_handler(finding, None)
    assert result["status"] == "success"
