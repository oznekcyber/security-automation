"""
S3 Responder Lambda — GuardDuty automated response for S3 data exfiltration findings.

Triggered by EventBridge when GuardDuty emits a HIGH/CRITICAL severity finding
of type Policy:S3/* or Exfiltration:S3/*.

Automated response actions:
1. Enable Block Public Access on the affected bucket (all four settings).
2. Apply a restrictive bucket policy that denies all public GetObject requests.
3. Collect recent S3 access events from CloudTrail for the bucket.
4. Notify TheHive, Splunk, and Slack.

IAM permissions required (least-privilege):
    s3:GetBucketPublicAccessBlock    — check current Block Public Access state
    s3:PutBucketPublicAccessBlock    — enable Block Public Access
    s3:GetBucketPolicy               — check existing bucket policy
    s3:PutBucketPolicy               — apply restrictive policy
    cloudtrail:LookupEvents          — fetch recent S3 access events
    sns:Publish                      — send finding to SNS notification topic
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _get_s3_client(region: str) -> Any:
    return boto3.client("s3", region_name=region)


def _get_cloudtrail_client(region: str) -> Any:
    return boto3.client("cloudtrail", region_name=region)


def _extract_bucket_name(finding: dict[str, Any]) -> str | None:
    """Extract the S3 bucket name from a GuardDuty finding."""
    resource = finding.get("resource", {})
    bucket_details = resource.get("s3BucketDetails", [])
    if bucket_details:
        return bucket_details[0].get("name")
    return None


def block_public_access(s3: Any, bucket_name: str) -> None:
    """
    Enable all four Block Public Access settings on the bucket.

    This is the fastest way to stop data leakage: it overrides any
    ACLs and bucket policies that grant public access.
    """
    logger.info("BLOCKING public access on bucket %s", bucket_name)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    logger.info("BLOCKED all public access on bucket %s", bucket_name)


def apply_restrictive_policy(s3: Any, bucket_name: str, account_id: str) -> None:
    """
    Apply a restrictive bucket policy that:
    1. Denies all s3:GetObject calls from principals outside this AWS account.
    2. Denies all s3:PutObject calls from principals outside this AWS account.

    This is belt-and-suspenders on top of Block Public Access.
    """
    logger.info("Applying restrictive bucket policy to %s", bucket_name)

    restrictive_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "GuardDutyDenyExternalGetObject",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {
                    "StringNotEquals": {
                        "aws:PrincipalAccount": account_id
                    }
                },
            },
            {
                "Sid": "GuardDutyDenyExternalPutObject",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {
                    "StringNotEquals": {
                        "aws:PrincipalAccount": account_id
                    }
                },
            },
        ],
    }

    try:
        s3.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(restrictive_policy),
        )
        logger.info("Applied restrictive policy to bucket %s", bucket_name)
    except ClientError as exc:
        # If the bucket already has a policy that blocks this, log and continue
        logger.warning("Could not apply bucket policy to %s: %s", bucket_name, exc)
        raise


def lookup_recent_s3_events(cloudtrail: Any, bucket_name: str, max_results: int = 20) -> list[dict[str, Any]]:
    """
    Fetch recent CloudTrail S3 data events for the affected bucket.

    Note: CloudTrail data events for S3 must be enabled separately; if not
    enabled, this returns an empty list without raising.
    """
    logger.info("Looking up recent CloudTrail events for bucket %s", bucket_name)
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=24)

    try:
        resp = cloudtrail.lookup_events(
            LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": bucket_name}],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=max_results,
        )
        events = resp.get("Events", [])
        simplified = [
            {
                "eventTime": str(e.get("EventTime", "")),
                "eventName": e.get("EventName", ""),
                "username": e.get("Username", ""),
                "resources": [r.get("ResourceName", "") for r in e.get("Resources", [])],
            }
            for e in events
        ]
        logger.info("Retrieved %d CloudTrail events for bucket %s", len(simplified), bucket_name)
        return simplified
    except (ClientError, NotImplementedError) as exc:
        logger.warning("CloudTrail lookup failed for bucket %s: %s", bucket_name, exc)
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
    account_id = finding.get("accountId", os.environ.get("AWS_ACCOUNT_ID", ""))

    logger.info(
        "S3 RESPONDER — processing finding %s (type=%s, severity=%s)",
        finding_id, finding_type, severity,
    )

    bucket_name = _extract_bucket_name(finding)
    if not bucket_name:
        logger.error("No bucket name found in finding %s", finding_id)
        return {"status": "error", "reason": "no_bucket_name", "finding_id": finding_id}

    s3 = _get_s3_client(region)
    cloudtrail = _get_cloudtrail_client(region)
    automated_actions: list[str] = []
    errors: list[str] = []

    # --- Step 1: Block public access (PRIORITY) ---
    try:
        block_public_access(s3, bucket_name)
        automated_actions.append(f"Blocked all public access on S3 bucket {bucket_name}")
    except ClientError as exc:
        error_msg = f"Failed to block public access on {bucket_name}: {exc}"
        logger.error(error_msg)
        errors.append(error_msg)

    # --- Step 2: Apply restrictive bucket policy ---
    try:
        apply_restrictive_policy(s3, bucket_name, account_id)
        automated_actions.append(f"Applied restrictive bucket policy to {bucket_name}")
    except ClientError as exc:
        error_msg = f"Failed to apply bucket policy to {bucket_name}: {exc}"
        logger.error(error_msg)
        errors.append(error_msg)

    # --- Step 3: Collect CloudTrail audit trail ---
    recent_events = lookup_recent_s3_events(cloudtrail, bucket_name)
    if recent_events:
        automated_actions.append(
            f"Collected {len(recent_events)} recent CloudTrail S3 events for bucket {bucket_name}"
        )
        logger.info("S3 CloudTrail events: %s", json.dumps(recent_events, default=str))

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
        "bucket_name": bucket_name,
        "automated_actions": automated_actions,
        "errors": errors,
        "cloudtrail_events_count": len(recent_events),
    }
    logger.info("S3 RESPONDER COMPLETE — %s", json.dumps(result))
    return result
