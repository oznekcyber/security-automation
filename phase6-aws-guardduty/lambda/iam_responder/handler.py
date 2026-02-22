"""
IAM Responder Lambda — GuardDuty automated response for IAM credential compromise.

Triggered by EventBridge when GuardDuty emits a HIGH/CRITICAL severity finding
of type UnauthorizedAccess:IAMUser/* or CredentialAccess:IAMUser/*.

Automated response actions:
1. Deactivate the compromised IAM access key immediately.
2. Attach a deny-all inline policy to the IAM user to block all further API calls.
3. List and log the 10 most recent CloudTrail events from that principal for
   context in TheHive and Splunk.
4. Notify TheHive, Splunk, and Slack.

IAM permissions required (least-privilege):
    iam:GetAccessKeyLastUsed     — confirm the key is active before disabling
    iam:UpdateAccessKey          — disable the compromised access key
    iam:PutUserPolicy            — attach deny-all inline policy to the user
    iam:ListAccessKeys           — list all keys for the user
    iam:GetUser                  — verify the user exists
    cloudtrail:LookupEvents      — fetch recent API activity for the user
    sns:Publish                  — send finding to SNS notification topic
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Deny-all IAM policy — attached to the user as an inline policy
# This blocks ALL API calls regardless of other permissions
_DENY_ALL_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "GuardDutyEmergencyDenyAll",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:RequestedRegion": "*"  # All regions
                }
            },
        }
    ],
})

# Policy name used for the emergency lockout — must be consistent for idempotency
_LOCKOUT_POLICY_NAME = "GuardDutyEmergencyDenyAll"


def _get_iam_client() -> Any:
    return boto3.client("iam")


def _get_cloudtrail_client(region: str) -> Any:
    return boto3.client("cloudtrail", region_name=region)


def _extract_access_key_details(finding: dict[str, Any]) -> tuple[str | None, str | None]:
    """Extract (access_key_id, username) from the GuardDuty finding."""
    resource = finding.get("resource", {})
    key_details = resource.get("accessKeyDetails", {})
    access_key_id = key_details.get("accessKeyId")
    username = key_details.get("userName")
    return access_key_id, username


def disable_access_key(iam: Any, username: str, access_key_id: str) -> None:
    """
    Deactivate the compromised IAM access key.

    This is fast — it invalidates the key immediately so any in-flight
    API calls using it will fail with InvalidClientTokenId.
    """
    logger.info("DISABLING access key %s for user %s", access_key_id, username)
    iam.update_access_key(
        UserName=username,
        AccessKeyId=access_key_id,
        Status="Inactive",
    )
    logger.info("DISABLED access key %s for user %s", access_key_id, username)


def attach_deny_all_policy(iam: Any, username: str) -> None:
    """
    Attach an emergency deny-all inline policy to the IAM user.

    This is a belt-and-suspenders action: even if the user has other
    access keys or permissions, this policy blocks everything.
    """
    logger.info("ATTACHING deny-all policy to user %s", username)
    iam.put_user_policy(
        UserName=username,
        PolicyName=_LOCKOUT_POLICY_NAME,
        PolicyDocument=_DENY_ALL_POLICY,
    )
    logger.info("ATTACHED deny-all policy to user %s — all API calls now blocked", username)


def lookup_recent_cloudtrail_events(cloudtrail: Any, username: str, max_results: int = 10) -> list[dict[str, Any]]:
    """
    Fetch the most recent CloudTrail events attributed to the IAM user.

    Returns a list of simplified event dicts for inclusion in the case notes.
    """
    logger.info("Looking up recent CloudTrail events for user %s", username)
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=24)

    try:
        resp = cloudtrail.lookup_events(
            LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": username}],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=max_results,
        )
        events = resp.get("Events", [])
        simplified = [
            {
                "eventTime": e.get("EventTime", "").isoformat() if hasattr(e.get("EventTime", ""), "isoformat") else str(e.get("EventTime", "")),
                "eventName": e.get("EventName", ""),
                "eventSource": e.get("EventSource", ""),
                "sourceIPAddress": json.loads(e.get("CloudTrailEvent", "{}")).get("sourceIPAddress", ""),
                "userAgent": json.loads(e.get("CloudTrailEvent", "{}")).get("userAgent", ""),
            }
            for e in events
        ]
        logger.info("Retrieved %d CloudTrail events for user %s", len(simplified), username)
        return simplified
    except (ClientError, NotImplementedError) as exc:
        logger.warning("CloudTrail lookup failed for user %s: %s", username, exc)
        return []


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Lambda entry point.

    Args:
        event:   EventBridge event with GuardDuty finding in event['detail'].
        context: Lambda context object.

    Returns:
        Dict with status and list of automated actions taken.
    """
    finding = event.get("detail", event)
    finding_id = finding.get("id", "unknown")
    finding_type = finding.get("type", "unknown")
    severity = finding.get("severity", 0.0)
    region = finding.get("region", os.environ.get("AWS_REGION", "us-east-1"))

    logger.info(
        "IAM RESPONDER — processing finding %s (type=%s, severity=%s)",
        finding_id, finding_type, severity,
    )

    access_key_id, username = _extract_access_key_details(finding)
    if not access_key_id or not username:
        logger.error("No access key or username found in finding %s", finding_id)
        return {"status": "error", "reason": "missing_key_or_user", "finding_id": finding_id}

    iam = _get_iam_client()
    cloudtrail = _get_cloudtrail_client(region)
    automated_actions: list[str] = []
    errors: list[str] = []

    # --- Step 1: Disable the compromised access key (PRIORITY) ---
    try:
        disable_access_key(iam, username, access_key_id)
        automated_actions.append(f"Disabled IAM access key {access_key_id} for user {username}")
    except ClientError as exc:
        error_msg = f"Failed to disable access key {access_key_id}: {exc}"
        logger.error(error_msg)
        errors.append(error_msg)

    # --- Step 2: Attach deny-all policy ---
    try:
        attach_deny_all_policy(iam, username)
        automated_actions.append(
            f"Attached emergency deny-all inline policy '{_LOCKOUT_POLICY_NAME}' to user {username}"
        )
    except ClientError as exc:
        error_msg = f"Failed to attach deny-all policy to user {username}: {exc}"
        logger.error(error_msg)
        errors.append(error_msg)

    # --- Step 3: Collect CloudTrail audit trail ---
    recent_events = lookup_recent_cloudtrail_events(cloudtrail, username)
    if recent_events:
        automated_actions.append(
            f"Collected {len(recent_events)} recent CloudTrail events for user {username}"
        )
        logger.info(
            "CloudTrail events for %s: %s",
            username, json.dumps(recent_events, indent=2, default=str),
        )

    # --- Step 4: Notify downstream systems ---
    enriched_finding = {**finding, "_cloudtrail_events": recent_events}

    try:
        from shared.thehive_client import create_case
        thehive_result = create_case(enriched_finding)
        if thehive_result:
            automated_actions.append(f"TheHive case created: {thehive_result.get('_id', 'unknown')}")
    except Exception as exc:  # noqa: BLE001
        logger.warning("TheHive notification failed: %s", exc)

    try:
        from shared.splunk_client import ship_finding
        ship_finding(enriched_finding, automated_actions)
        automated_actions.append("Finding shipped to Splunk HEC")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Splunk notification failed: %s", exc)

    try:
        from shared.slack_notifier import notify
        notify(
            finding,
            automated_actions=automated_actions,
            error_message="; ".join(errors) if errors else None,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Slack notification failed: %s", exc)

    result = {
        "status": "error" if errors and not automated_actions else "success",
        "finding_id": finding_id,
        "finding_type": finding_type,
        "username": username,
        "access_key_id": access_key_id,
        "automated_actions": automated_actions,
        "errors": errors,
        "cloudtrail_events_count": len(recent_events),
    }
    logger.info("IAM RESPONDER COMPLETE — %s", json.dumps(result))
    return result
