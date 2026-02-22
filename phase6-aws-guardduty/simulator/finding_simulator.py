# simulator/finding_simulator.py - full implementation
"""
GuardDuty Finding Simulator
============================
Generates realistic mock GuardDuty finding events for local testing of
Lambda response handlers without a live AWS GuardDuty detector.

Usage:
    python finding_simulator.py --type ec2 --output event
    python finding_simulator.py --type iam --output json
    python finding_simulator.py --type s3 --output event --severity 9.0
"""

from __future__ import annotations

import argparse
import json
import random
import string
import uuid
from datetime import datetime, timezone
from typing import Any

FINDING_TYPES = {
    "ec2": "UnauthorizedAccess:EC2/SSHBruteForce",
    "iam": "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
    "s3":  "Policy:S3/BucketBlockPublicAccessDisabled",
}


def _random_id(length: int = 32) -> str:
    return "".join(random.choices(string.hexdigits[:16], k=length))


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def make_ec2_finding(severity: float = 8.0, account_id: str = "123456789012", region: str = "us-east-1") -> dict[str, Any]:
    """Return a GuardDuty UnauthorizedAccess:EC2/SSHBruteForce finding."""
    instance_id = f"i-{_random_id(17)[:17]}"
    finding_id = _random_id(32)
    return {
        "schemaVersion": "2.0",
        "accountId": account_id,
        "region": region,
        "partition": "aws",
        "id": finding_id,
        "arn": f"arn:aws:guardduty:{region}:{account_id}:detector/abc123/finding/{finding_id}",
        "type": FINDING_TYPES["ec2"],
        "title": "SSH brute force attacks against EC2 instance.",
        "description": (
            f"EC2 instance {instance_id} is performing or is a target of SSH brute force attacks."
        ),
        "severity": severity,
        "createdAt": _iso_now(),
        "updatedAt": _iso_now(),
        "service": {
            "serviceName": "guardduty",
            "detectorId": "abc123def456abc123def456abc123de",
            "action": {
                "actionType": "NETWORK_CONNECTION",
                "networkConnectionAction": {
                    "connectionDirection": "INBOUND",
                    "remoteIpDetails": {
                        "ipAddressV4": "185.220.101.1",
                        "country": {"countryName": "Germany"},
                        "organization": {"asn": "205100", "asnOrg": "F3 Netze e.V."},
                    },
                    "localPortDetails": {"port": 22, "portName": "SSH"},
                    "protocol": "TCP",
                    "blocked": False,
                },
            },
            "resourceRole": "TARGET",
        },
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId": instance_id,
                "instanceType": "t3.medium",
                "launchTime": _iso_now(),
                "imageId": "ami-0abcdef1234567890",
                "instanceState": "running",
                "availabilityZone": f"{region}a",
                "tags": [{"key": "Name", "value": "web-server-01"}],
                "networkInterfaces": [
                    {
                        "networkInterfaceId": f"eni-{_random_id(17)[:17]}",
                        "subnetId": f"subnet-{_random_id(8)[:8]}",
                        "vpcId": f"vpc-{_random_id(8)[:8]}",
                        "privateDnsName": f"ip-10-0-1-42.{region}.compute.internal",
                        "privateIpAddress": "10.0.1.42",
                        "publicDnsName": f"ec2-54-{random.randint(100,255)}-{random.randint(0,255)}-{random.randint(0,255)}.compute-1.amazonaws.com",
                        "publicIp": f"54.{random.randint(100,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
                        "securityGroups": [
                            {"groupId": f"sg-{_random_id(8)[:8]}", "groupName": "web-sg"}
                        ],
                    }
                ],
                "iamInstanceProfile": {
                    "arn": f"arn:aws:iam::{account_id}:instance-profile/web-server-role",
                    "id": _random_id(20),
                },
            },
        },
    }


def make_iam_finding(severity: float = 8.0, account_id: str = "123456789012", region: str = "us-east-1") -> dict[str, Any]:
    """Return a GuardDuty UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B finding."""
    finding_id = _random_id(32)
    access_key_id = f"AKIA{_random_id(16).upper()[:16]}"
    username = "svc-deploy-user"
    return {
        "schemaVersion": "2.0",
        "accountId": account_id,
        "region": region,
        "partition": "aws",
        "id": finding_id,
        "arn": f"arn:aws:guardduty:{region}:{account_id}:detector/abc123/finding/{finding_id}",
        "type": FINDING_TYPES["iam"],
        "title": "Unusual console login for IAM user.",
        "description": (
            f"API caller {username} invoked GetConsoleLoginLink from an unusual location."
        ),
        "severity": severity,
        "createdAt": _iso_now(),
        "updatedAt": _iso_now(),
        "service": {
            "serviceName": "guardduty",
            "detectorId": "abc123def456abc123def456abc123de",
            "action": {
                "actionType": "AWS_API_CALL",
                "awsApiCallAction": {
                    "api": "GetConsoleLoginLink",
                    "serviceName": "signin.amazonaws.com",
                    "callerType": "Remote IP",
                    "remoteIpDetails": {
                        "ipAddressV4": "91.108.4.1",
                        "country": {"countryName": "Russia"},
                        "organization": {"asn": "59930", "asnOrg": "Telegram Messenger Inc"},
                    },
                },
            },
            "resourceRole": "TARGET",
        },
        "resource": {
            "resourceType": "AccessKey",
            "accessKeyDetails": {
                "accessKeyId": access_key_id,
                "principalId": username,
                "userType": "IAMUser",
                "userName": username,
            },
        },
    }


def make_s3_finding(severity: float = 8.0, account_id: str = "123456789012", region: str = "us-east-1") -> dict[str, Any]:
    """Return a GuardDuty Policy:S3/BucketBlockPublicAccessDisabled finding."""
    finding_id = _random_id(32)
    bucket_name = f"my-data-bucket-{_random_id(8)[:8]}"
    return {
        "schemaVersion": "2.0",
        "accountId": account_id,
        "region": region,
        "partition": "aws",
        "id": finding_id,
        "arn": f"arn:aws:guardduty:{region}:{account_id}:detector/abc123/finding/{finding_id}",
        "type": FINDING_TYPES["s3"],
        "title": "S3 Block Public Access was disabled for a bucket.",
        "description": (
            f"S3 Block Public Access was disabled for Amazon S3 bucket {bucket_name}."
        ),
        "severity": severity,
        "createdAt": _iso_now(),
        "updatedAt": _iso_now(),
        "service": {
            "serviceName": "guardduty",
            "detectorId": "abc123def456abc123def456abc123de",
            "action": {
                "actionType": "AWS_API_CALL",
                "awsApiCallAction": {
                    "api": "PutBucketPublicAccessBlock",
                    "serviceName": "s3.amazonaws.com",
                    "callerType": "Remote IP",
                    "remoteIpDetails": {
                        "ipAddressV4": "203.0.113.99",
                        "country": {"countryName": "Unknown"},
                        "organization": {"asn": "64496", "asnOrg": "TEST-NET"},
                    },
                },
            },
            "resourceRole": "TARGET",
        },
        "resource": {
            "resourceType": "S3Bucket",
            "s3BucketDetails": [
                {
                    "arn": f"arn:aws:s3:::{bucket_name}",
                    "name": bucket_name,
                    "type": "Destination",
                    "createdAt": _iso_now(),
                    "owner": {"id": _random_id(64)},
                    "tags": [{"key": "Environment", "value": "production"}],
                    "defaultServerSideEncryption": {"encryptionType": "aws:kms"},
                    "publicAccess": {
                        "permissionConfiguration": {
                            "bucketLevelPermissions": {
                                "blockPublicAccess": {
                                    "ignorePublicAcls": False,
                                    "restrictPublicBuckets": False,
                                    "blockPublicAcls": False,
                                    "blockPublicPolicy": False,
                                }
                            }
                        },
                        "effectivePermission": "PUBLIC",
                    },
                }
            ],
        },
    }


MAKERS = {
    "ec2": make_ec2_finding,
    "iam": make_iam_finding,
    "s3": make_s3_finding,
}


def wrap_eventbridge(finding: dict[str, Any]) -> dict[str, Any]:
    """Wrap a GuardDuty finding in an EventBridge event envelope."""
    return {
        "version": "0",
        "id": str(uuid.uuid4()),
        "source": "aws.guardduty",
        "account": finding["accountId"],
        "time": _iso_now(),
        "region": finding["region"],
        "resources": [finding["arn"]],
        "detail-type": "GuardDuty Finding",
        "detail": finding,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate mock GuardDuty findings")
    parser.add_argument("--type", choices=["ec2", "iam", "s3"], default="ec2",
                        help="Finding type to generate")
    parser.add_argument("--output", choices=["json", "event"], default="event",
                        help="Output format: raw finding JSON or EventBridge event envelope")
    parser.add_argument("--severity", type=float, default=8.0,
                        help="Finding severity (1.0-9.0)")
    parser.add_argument("--account-id", default="123456789012",
                        help="AWS account ID to embed in the finding")
    parser.add_argument("--region", default="us-east-1",
                        help="AWS region to embed in the finding")
    args = parser.parse_args()

    finding = MAKERS[args.type](
        severity=args.severity,
        account_id=args.account_id,
        region=args.region,
    )

    if args.output == "event":
        output = wrap_eventbridge(finding)
    else:
        output = finding

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
