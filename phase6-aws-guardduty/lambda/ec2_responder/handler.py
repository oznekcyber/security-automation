"""
EC2 Responder Lambda — GuardDuty automated response for EC2 compromise findings.

Triggered by EventBridge when GuardDuty emits a HIGH/CRITICAL severity finding
of type UnauthorizedAccess:EC2/* or Backdoor:EC2/* or similar.

Automated response actions (in order of execution for speed):
1. Replace the instance's security groups with the quarantine security group
   (deny-all) — this is the fastest containment action.
2. Create an EBS snapshot of every attached volume for forensic preservation.
3. Tag the instance with investigation metadata (timestamp, finding ID, analyst).
4. Attempt to collect memory artefacts via SSM Run Command if SSM agent is
   available (best-effort, does not block containment).
5. Notify TheHive (create case), Splunk (ship finding), and Slack.

IAM permissions required (least-privilege, see CDK lambda_stack.py for policy):
    ec2:DescribeInstances         — look up instance details by ID
    ec2:DescribeSecurityGroups    — find the quarantine security group by name
    ec2:ModifyInstanceAttribute   — replace security groups (containment)
    ec2:CreateSnapshot            — forensic EBS snapshot
    ec2:DescribeVolumes           — list attached volumes
    ec2:CreateTags                — tag instance and snapshots with metadata
    ssm:SendCommand               — attempt memory collection (best-effort)
    ssm:GetCommandInvocation      — poll SSM command result
    sns:Publish                   — send finding to SNS notification topic
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

# Shared modules — packaged alongside this Lambda via Lambda layers or bundling
import sys
sys.path.insert(0, "/opt/python")  # Lambda layer path

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _get_ec2_client(region: str) -> Any:
    return boto3.client("ec2", region_name=region)


def _get_ssm_client(region: str) -> Any:
    return boto3.client("ssm", region_name=region)


def _get_sns_client(region: str) -> Any:
    return boto3.client("sns", region_name=region)


def _extract_instance_id(finding: dict[str, Any]) -> str | None:
    """Extract the EC2 instance ID from a GuardDuty finding."""
    resource = finding.get("resource", {})
    instance_details = resource.get("instanceDetails", {})
    return instance_details.get("instanceId")


def _extract_region(finding: dict[str, Any]) -> str:
    return finding.get("region", os.environ.get("AWS_REGION", "us-east-1"))


def isolate_instance(ec2: Any, instance_id: str, quarantine_sg_id: str) -> list[str]:
    """
    Replace all security groups on the instance with the quarantine group.
    This cuts off all network access immediately.

    Returns:
        List of original security group IDs (for the audit log).
    """
    logger.info("ISOLATING instance %s — fetching current security groups", instance_id)
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    reservations = resp.get("Reservations", [])
    if not reservations:
        raise ValueError(f"Instance {instance_id} not found")

    instance = reservations[0]["Instances"][0]
    original_sgs = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]

    logger.info(
        "ISOLATING instance %s — original SGs: %s → quarantine SG: %s",
        instance_id, original_sgs, quarantine_sg_id,
    )
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[quarantine_sg_id],
    )
    logger.info("ISOLATED instance %s — all traffic blocked", instance_id)
    return original_sgs


def snapshot_volumes(ec2: Any, instance_id: str, finding_id: str) -> list[str]:
    """
    Create EBS snapshots for all volumes attached to the instance.

    Returns:
        List of snapshot IDs created.
    """
    logger.info("SNAPSHOTTING volumes for instance %s", instance_id)
    resp = ec2.describe_volumes(
        Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
    )
    volumes = resp.get("Volumes", [])
    snapshot_ids = []

    for vol in volumes:
        vol_id = vol["VolumeId"]
        logger.info("Creating snapshot for volume %s (instance %s)", vol_id, instance_id)
        snap = ec2.create_snapshot(
            VolumeId=vol_id,
            Description=f"Forensic snapshot — GuardDuty finding {finding_id} — instance {instance_id}",
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "Purpose", "Value": "forensic"},
                        {"Key": "GuardDutyFindingId", "Value": finding_id},
                        {"Key": "SourceInstance", "Value": instance_id},
                        {"Key": "AutomatedBy", "Value": "guardduty-ec2-responder"},
                    ],
                }
            ],
        )
        snap_id = snap["SnapshotId"]
        snapshot_ids.append(snap_id)
        logger.info("Snapshot %s created for volume %s", snap_id, vol_id)

    return snapshot_ids


def tag_instance(ec2: Any, instance_id: str, finding: dict[str, Any], snapshot_ids: list[str], original_sgs: list[str]) -> None:
    """Tag the instance with investigation metadata for forensic chain-of-custody."""
    finding_id = finding.get("id", "unknown")
    finding_type = finding.get("type", "unknown")
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    tags = [
        {"Key": "SecurityStatus", "Value": "QUARANTINED"},
        {"Key": "GuardDutyFindingId", "Value": finding_id},
        {"Key": "GuardDutyFindingType", "Value": finding_type},
        {"Key": "QuarantinedAt", "Value": timestamp},
        {"Key": "AutomatedResponseBy", "Value": "guardduty-ec2-responder"},
        {"Key": "ForensicSnapshots", "Value": ",".join(snapshot_ids)},
        {"Key": "OriginalSecurityGroups", "Value": ",".join(original_sgs)},
    ]

    ec2.create_tags(Resources=[instance_id], Tags=tags)
    logger.info("Tagged instance %s with investigation metadata (finding=%s)", instance_id, finding_id)


def collect_memory_via_ssm(ssm: Any, instance_id: str, finding_id: str) -> str | None:
    """
    Attempt to trigger memory collection on the instance via SSM Run Command.

    This is best-effort: if the instance does not have SSM agent or the agent
    is offline, we log a warning and continue without blocking containment.

    Returns:
        SSM Command ID if dispatched, None otherwise.
    """
    logger.info("Attempting SSM memory collection on instance %s", instance_id)
    # LiME / avml memory collection — basic proof-of-concept command
    # In production, replace with a proper memory acquisition script stored in S3
    memory_cmd = (
        "#!/bin/bash\n"
        f"FINDING_ID={finding_id}\n"
        "TIMESTAMP=$(date +%Y%m%dT%H%M%SZ)\n"
        "OUTPUT_FILE=/tmp/memory-dump-$TIMESTAMP.lime\n"
        "if command -v avml &>/dev/null; then\n"
        "  avml $OUTPUT_FILE && echo 'Memory dump saved to '$OUTPUT_FILE\n"
        "else\n"
        "  echo 'avml not available — skipping memory dump'\n"
        "fi\n"
        "ps auxf > /tmp/process-list-$TIMESTAMP.txt\n"
        "netstat -tulpn 2>/dev/null > /tmp/network-connections-$TIMESTAMP.txt\n"
        "echo 'Basic forensic artefacts collected'\n"
    )

    try:
        resp = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [memory_cmd]},
            Comment=f"Forensic data collection — GuardDuty finding {finding_id}",
            TimeoutSeconds=60,
        )
        command_id = resp["Command"]["CommandId"]
        logger.info("SSM command %s dispatched for memory collection on %s", command_id, instance_id)
        return command_id
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        logger.warning(
            "SSM memory collection failed for instance %s (error=%s) — continuing without memory",
            instance_id, error_code,
        )
        return None


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Lambda entry point.

    Args:
        event:   EventBridge event with GuardDuty finding in event['detail'].
        context: Lambda context object.

    Returns:
        Dict with status and list of automated actions taken.
    """
    finding = event.get("detail", event)  # Support direct invocation with raw finding
    finding_id = finding.get("id", "unknown")
    finding_type = finding.get("type", "unknown")
    severity = finding.get("severity", 0.0)
    region = _extract_region(finding)

    logger.info(
        "EC2 RESPONDER — processing finding %s (type=%s, severity=%s, region=%s)",
        finding_id, finding_type, severity, region,
    )

    instance_id = _extract_instance_id(finding)
    if not instance_id:
        logger.error("No instance ID found in finding %s — cannot respond", finding_id)
        return {"status": "error", "reason": "no_instance_id", "finding_id": finding_id}

    quarantine_sg_name = os.environ.get("QUARANTINE_SG_NAME", "guardduty-quarantine")
    ec2 = _get_ec2_client(region)
    ssm = _get_ssm_client(region)

    # Resolve the quarantine security group ID by name
    try:
        sg_resp = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": [quarantine_sg_name]}]
        )
        sgs = sg_resp.get("SecurityGroups", [])
        if not sgs:
            raise ValueError(f"Quarantine security group '{quarantine_sg_name}' not found")
        quarantine_sg_id = sgs[0]["GroupId"]
        logger.info("Quarantine SG resolved: %s (%s)", quarantine_sg_id, quarantine_sg_name)
    except (ClientError, ValueError) as exc:
        logger.error("Failed to resolve quarantine SG: %s", exc)
        return {"status": "error", "reason": str(exc), "finding_id": finding_id}

    automated_actions: list[str] = []
    errors: list[str] = []

    # --- Step 1: Isolate the instance (PRIORITY — fastest containment) ---
    try:
        original_sgs = isolate_instance(ec2, instance_id, quarantine_sg_id)
        automated_actions.append(
            f"Isolated instance {instance_id} by replacing SGs {original_sgs} with quarantine SG {quarantine_sg_id}"
        )
    except (ClientError, ValueError) as exc:
        error_msg = f"Failed to isolate instance {instance_id}: {exc}"
        logger.error(error_msg)
        errors.append(error_msg)
        original_sgs = []

    # --- Step 2: Snapshot volumes for forensic preservation ---
    try:
        snapshot_ids = snapshot_volumes(ec2, instance_id, finding_id)
        automated_actions.append(
            f"Created forensic EBS snapshots for instance {instance_id}: {snapshot_ids}"
        )
    except ClientError as exc:
        error_msg = f"Failed to snapshot volumes for {instance_id}: {exc}"
        logger.error(error_msg)
        errors.append(error_msg)
        snapshot_ids = []

    # --- Step 3: Tag instance with investigation metadata ---
    try:
        tag_instance(ec2, instance_id, finding, snapshot_ids, original_sgs)
        automated_actions.append(f"Tagged instance {instance_id} with investigation metadata")
    except ClientError as exc:
        error_msg = f"Failed to tag instance {instance_id}: {exc}"
        logger.error(error_msg)
        errors.append(error_msg)

    # --- Step 4: Memory collection via SSM (best-effort, non-blocking) ---
    ssm_command_id = collect_memory_via_ssm(ssm, instance_id, finding_id)
    if ssm_command_id:
        automated_actions.append(
            f"Dispatched SSM forensic collection command {ssm_command_id} on instance {instance_id}"
        )
    else:
        automated_actions.append(f"SSM memory collection skipped (agent not available or instance offline)")

    # --- Step 5: Notify downstream systems ---
    # Import shared modules here to keep Lambda imports lazy and avoid cold-start overhead
    try:
        from shared.thehive_client import create_case
        thehive_result = create_case(finding)
        if thehive_result:
            automated_actions.append(f"TheHive case created: {thehive_result.get('_id', 'unknown')}")
    except Exception as exc:  # noqa: BLE001
        logger.warning("TheHive notification failed: %s", exc)

    try:
        from shared.splunk_client import ship_finding
        ship_finding(finding, automated_actions)
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
        "instance_id": instance_id,
        "automated_actions": automated_actions,
        "errors": errors,
    }
    logger.info("EC2 RESPONDER COMPLETE — %s", json.dumps(result))
    return result
