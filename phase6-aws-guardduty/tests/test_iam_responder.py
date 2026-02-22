"""
Tests for the IAM GuardDuty responder Lambda handler.

All tests use moto to mock AWS API calls — no real AWS credentials needed.
Run with: pytest tests/test_iam_responder.py -v
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

_iam_handler_path = os.path.join(
    os.path.dirname(__file__), "..", "lambda", "iam_responder", "handler.py"
)
_spec = importlib.util.spec_from_file_location("iam_handler_module", _iam_handler_path)
_iam_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_iam_module)

disable_access_key = _iam_module.disable_access_key
attach_deny_all_policy = _iam_module.attach_deny_all_policy
iam_handler = _iam_module.handler
_LOCKOUT_POLICY_NAME = _iam_module._LOCKOUT_POLICY_NAME


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
def iam_client():
    return boto3.client("iam", region_name="us-east-1")


@pytest.fixture
def mock_iam_user(iam_client):
    """Create a test IAM user with an active access key."""
    username = "test-compromised-user"
    iam_client.create_user(UserName=username)
    key_resp = iam_client.create_access_key(UserName=username)
    access_key_id = key_resp["AccessKey"]["AccessKeyId"]
    return {"username": username, "access_key_id": access_key_id}


def _make_iam_finding(username: str, access_key_id: str) -> dict:
    return {
        "id": "iam-finding-001",
        "type": "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
        "severity": 8.0,
        "region": "us-east-1",
        "accountId": "123456789012",
        "description": "Unusual console login detected",
        "resource": {
            "resourceType": "AccessKey",
            "accessKeyDetails": {
                "accessKeyId": access_key_id,
                "userName": username,
                "userType": "IAMUser",
                "principalId": username,
            },
        },
    }



def test_disable_access_key_deactivates_key(mock_iam_user, iam_client):
    """disable_access_key should set the key status to Inactive."""
    username = mock_iam_user["username"]
    access_key_id = mock_iam_user["access_key_id"]

    disable_access_key(iam_client, username, access_key_id)

    keys = iam_client.list_access_keys(UserName=username)["AccessKeyMetadata"]
    key = next(k for k in keys if k["AccessKeyId"] == access_key_id)
    assert key["Status"] == "Inactive", f"Expected Inactive, got {key['Status']}"



def test_attach_deny_all_policy(mock_iam_user, iam_client):
    """attach_deny_all_policy should attach an inline deny-all policy to the user."""
    username = mock_iam_user["username"]

    attach_deny_all_policy(iam_client, username)

    policies = iam_client.list_user_policies(UserName=username)["PolicyNames"]
    assert _LOCKOUT_POLICY_NAME in policies, f"Policy '{_LOCKOUT_POLICY_NAME}' not found in {policies}"

    # Verify the policy content is deny-all
    policy_doc = iam_client.get_user_policy(UserName=username, PolicyName=_LOCKOUT_POLICY_NAME)
    import urllib.parse
    raw = policy_doc["PolicyDocument"]
    # moto returns a dict; real AWS returns a URL-encoded string
    if isinstance(raw, dict):
        policy_json = raw
    else:
        policy_json = json.loads(urllib.parse.unquote(raw))
    stmt = policy_json["Statement"][0]
    assert stmt["Effect"] == "Deny"
    assert stmt["Action"] == "*"
    assert stmt["Resource"] == "*"



def test_handler_end_to_end_success(mock_iam_user):
    """Full handler should disable key and attach deny-all policy."""
    username = mock_iam_user["username"]
    access_key_id = mock_iam_user["access_key_id"]

    finding = _make_iam_finding(username, access_key_id)
    result = iam_handler({"detail": finding}, None)

    assert result["status"] == "success"
    assert result["username"] == username
    assert result["access_key_id"] == access_key_id
    assert len(result["automated_actions"]) >= 2

    # Verify the key is now disabled
    iam = boto3.client("iam")
    keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
    key = next(k for k in keys if k["AccessKeyId"] == access_key_id)
    assert key["Status"] == "Inactive"

    # Verify deny-all policy is attached
    policies = iam.list_user_policies(UserName=username)["PolicyNames"]
    assert _LOCKOUT_POLICY_NAME in policies



def test_handler_missing_access_key_details():
    """Handler should return error if no access key details in finding."""
    finding = {
        "id": "iam-finding-no-key",
        "type": "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
        "severity": 8.0,
        "region": "us-east-1",
        "accountId": "123456789012",
        "resource": {"resourceType": "AccessKey", "accessKeyDetails": {}},
    }
    result = iam_handler({"detail": finding}, None)
    assert result["status"] == "error"
    assert result["reason"] == "missing_key_or_user"



def test_handler_direct_finding_no_envelope(mock_iam_user):
    """Handler should work even if called with raw finding (no EventBridge envelope)."""
    username = mock_iam_user["username"]
    access_key_id = mock_iam_user["access_key_id"]

    finding = _make_iam_finding(username, access_key_id)
    # Pass finding directly without wrapping in {'detail': ...}
    result = iam_handler(finding, None)

    assert result["status"] == "success"
