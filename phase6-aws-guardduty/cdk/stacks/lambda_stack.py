"""
Lambda Stack — CDK stack that provisions:
  - EC2, IAM, and S3 responder Lambda functions
  - Least-privilege IAM execution roles for each Lambda
  - Lambda layers for shared code
  - EventBridge rules that route GuardDuty findings to the correct handler

Every IAM permission is documented with a reason.
"""

from __future__ import annotations

import os

import aws_cdk as cdk
from aws_cdk import (
    Duration,
    Stack,
    Tags,
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_logs as logs,
    aws_ssm as ssm,
)
from constructs import Construct

from stacks.guardduty_stack import GuardDutyStack

_LAMBDA_TIMEOUT = Duration.seconds(30)
_LAMBDA_RUNTIME = lambda_.Runtime.PYTHON_3_11
_LOG_RETENTION = logs.RetentionDays.ONE_MONTH

# EventBridge pattern to match only HIGH (7-9) and CRITICAL severity findings
_HIGH_SEVERITY_PATTERN = events.EventPattern(
    source=["aws.guardduty"],
    detail_type=["GuardDuty Finding"],
    detail={
        "severity": [{"numeric": [">=", 7.0]}],
    },
)

# Finding type prefixes for each responder
_EC2_FINDING_PREFIXES = [
    "UnauthorizedAccess:EC2/",
    "Backdoor:EC2/",
    "Trojan:EC2/",
    "Recon:EC2/",
    "CryptoCurrency:EC2/",
    "Behavior:EC2/",
]

_IAM_FINDING_PREFIXES = [
    "UnauthorizedAccess:IAMUser/",
    "CredentialAccess:IAMUser/",
    "Persistence:IAMUser/",
    "PrivilegeEscalation:IAMUser/",
    "Recon:IAMUser/",
    "Stealth:IAMUser/",
    "Impact:IAMUser/",
]

_S3_FINDING_PREFIXES = [
    "Policy:S3/",
    "Exfiltration:S3/",
    "Impact:S3/",
    "Stealth:S3/",
    "Recon:S3/",
]


def _ec2_type_filter(prefixes: list[str]) -> list[dict]:
    return [{"prefix": p} for p in prefixes]


class LambdaStack(Stack):
    """
    Lambda functions + IAM roles + EventBridge routing for GuardDuty response.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        guardduty_stack: GuardDutyStack,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        lambda_dir = os.path.join(os.path.dirname(__file__), "..", "..", "lambda")

        # ------------------------------------------------------------------ #
        # Shared Lambda Layer — thehive_client, splunk_client, slack_notifier #
        # ------------------------------------------------------------------ #
        shared_layer = lambda_.LayerVersion(
            self,
            "SharedLayer",
            code=lambda_.Code.from_asset(os.path.join(lambda_dir, "shared")),
            compatible_runtimes=[_LAMBDA_RUNTIME],
            description="Shared clients: TheHive, Splunk HEC, Slack",
        )

        # ------------------------------------------------------------------ #
        # EC2 Responder                                                       #
        # ------------------------------------------------------------------ #
        ec2_role = iam.Role(
            self,
            "EC2ResponderRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="EC2 GuardDuty responder — isolate, snapshot, tag, SSM",
            managed_policies=[
                # CloudWatch Logs — required for all Lambda functions
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ],
        )
        # ec2:DescribeInstances — look up instance details to find current SGs
        # ec2:DescribeSecurityGroups — resolve quarantine SG name to ID
        # ec2:ModifyInstanceAttribute — replace SGs with quarantine group (CONTAINMENT)
        # ec2:DescribeVolumes — list attached volumes for snapshot
        # ec2:CreateSnapshot — forensic EBS snapshot
        # ec2:CreateTags — tag instance and snapshots with investigation metadata
        ec2_role.add_to_policy(
            iam.PolicyStatement(
                sid="EC2ContainmentAndForensics",
                effect=iam.Effect.ALLOW,
                actions=[
                    "ec2:DescribeInstances",
                    "ec2:DescribeSecurityGroups",
                    "ec2:ModifyInstanceAttribute",
                    "ec2:DescribeVolumes",
                    "ec2:CreateSnapshot",
                    "ec2:CreateTags",
                ],
                resources=["*"],  # Must be * for Describe/Create operations
                conditions={
                    "StringEquals": {
                        "aws:RequestedRegion": self.region
                    }
                },
            )
        )
        # ssm:SendCommand — dispatch forensic collection script to the instance
        # ssm:GetCommandInvocation — poll SSM command status
        ec2_role.add_to_policy(
            iam.PolicyStatement(
                sid="SSMForensicCollection",
                effect=iam.Effect.ALLOW,
                actions=["ssm:SendCommand", "ssm:GetCommandInvocation"],
                resources=["*"],
                conditions={
                    "StringEquals": {
                        "aws:RequestedRegion": self.region
                    }
                },
            )
        )
        # ssm:GetParameter — read configuration from SSM Parameter Store
        ec2_role.add_to_policy(
            iam.PolicyStatement(
                sid="SSMParameterRead",
                effect=iam.Effect.ALLOW,
                actions=["ssm:GetParameter", "ssm:GetParameters"],
                resources=[
                    f"arn:aws:ssm:{self.region}:{self.account}:parameter/guardduty-response/*"
                ],
            )
        )

        self.ec2_fn = lambda_.Function(
            self,
            "EC2Responder",
            function_name="guardduty-ec2-responder",
            runtime=_LAMBDA_RUNTIME,
            handler="handler.handler",
            code=lambda_.Code.from_asset(os.path.join(lambda_dir, "ec2_responder")),
            role=ec2_role,
            timeout=_LAMBDA_TIMEOUT,
            memory_size=256,
            layers=[shared_layer],
            environment={
                "QUARANTINE_SG_NAME": "guardduty-quarantine",
                "QUARANTINE_SG_ID": guardduty_stack.quarantine_sg.security_group_id,
                "SNS_TOPIC_ARN": guardduty_stack.findings_topic.topic_arn,
            },
            log_retention=_LOG_RETENTION,
            description="Isolate, snapshot, and tag compromised EC2 instances",
        )
        Tags.of(self.ec2_fn).add("Component", "ec2-responder")

        # ------------------------------------------------------------------ #
        # IAM Responder                                                       #
        # ------------------------------------------------------------------ #
        iam_role = iam.Role(
            self,
            "IAMResponderRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="IAM GuardDuty responder — disable key, deny-all policy, CloudTrail",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ],
        )
        # iam:UpdateAccessKey — disable the compromised access key (CONTAINMENT)
        # iam:PutUserPolicy — attach deny-all inline policy (belt-and-suspenders)
        # iam:ListAccessKeys — enumerate all keys for the user
        # iam:GetUser — verify user exists before attempting disable
        iam_role.add_to_policy(
            iam.PolicyStatement(
                sid="IAMContainment",
                effect=iam.Effect.ALLOW,
                actions=[
                    "iam:UpdateAccessKey",
                    "iam:PutUserPolicy",
                    "iam:ListAccessKeys",
                    "iam:GetUser",
                ],
                resources=["arn:aws:iam::*:user/*"],
            )
        )
        # cloudtrail:LookupEvents — fetch recent API activity for the user
        iam_role.add_to_policy(
            iam.PolicyStatement(
                sid="CloudTrailAudit",
                effect=iam.Effect.ALLOW,
                actions=["cloudtrail:LookupEvents"],
                resources=["*"],  # LookupEvents does not support resource-level restrictions
            )
        )
        iam_role.add_to_policy(
            iam.PolicyStatement(
                sid="SSMParameterRead",
                effect=iam.Effect.ALLOW,
                actions=["ssm:GetParameter", "ssm:GetParameters"],
                resources=[
                    f"arn:aws:ssm:{self.region}:{self.account}:parameter/guardduty-response/*"
                ],
            )
        )

        self.iam_fn = lambda_.Function(
            self,
            "IAMResponder",
            function_name="guardduty-iam-responder",
            runtime=_LAMBDA_RUNTIME,
            handler="handler.handler",
            code=lambda_.Code.from_asset(os.path.join(lambda_dir, "iam_responder")),
            role=iam_role,
            timeout=_LAMBDA_TIMEOUT,
            memory_size=256,
            layers=[shared_layer],
            environment={
                "SNS_TOPIC_ARN": guardduty_stack.findings_topic.topic_arn,
            },
            log_retention=_LOG_RETENTION,
            description="Disable compromised IAM access keys and lock out users",
        )
        Tags.of(self.iam_fn).add("Component", "iam-responder")

        # ------------------------------------------------------------------ #
        # S3 Responder                                                        #
        # ------------------------------------------------------------------ #
        s3_role = iam.Role(
            self,
            "S3ResponderRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="S3 GuardDuty responder — block public access, restrictive policy",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ],
        )
        # s3:PutBucketPublicAccessBlock — enable Block Public Access (CONTAINMENT)
        # s3:GetBucketPublicAccessBlock — read current state before modifying
        # s3:PutBucketPolicy — apply restrictive bucket policy
        # s3:GetBucketPolicy — read existing policy before replacing
        s3_role.add_to_policy(
            iam.PolicyStatement(
                sid="S3Containment",
                effect=iam.Effect.ALLOW,
                actions=[
                    "s3:PutBucketPublicAccessBlock",
                    "s3:GetBucketPublicAccessBlock",
                    "s3:PutBucketPolicy",
                    "s3:GetBucketPolicy",
                ],
                resources=["arn:aws:s3:::*"],
            )
        )
        s3_role.add_to_policy(
            iam.PolicyStatement(
                sid="CloudTrailAudit",
                effect=iam.Effect.ALLOW,
                actions=["cloudtrail:LookupEvents"],
                resources=["*"],
            )
        )
        s3_role.add_to_policy(
            iam.PolicyStatement(
                sid="SSMParameterRead",
                effect=iam.Effect.ALLOW,
                actions=["ssm:GetParameter", "ssm:GetParameters"],
                resources=[
                    f"arn:aws:ssm:{self.region}:{self.account}:parameter/guardduty-response/*"
                ],
            )
        )

        self.s3_fn = lambda_.Function(
            self,
            "S3Responder",
            function_name="guardduty-s3-responder",
            runtime=_LAMBDA_RUNTIME,
            handler="handler.handler",
            code=lambda_.Code.from_asset(os.path.join(lambda_dir, "s3_responder")),
            role=s3_role,
            timeout=_LAMBDA_TIMEOUT,
            memory_size=256,
            layers=[shared_layer],
            environment={
                "SNS_TOPIC_ARN": guardduty_stack.findings_topic.topic_arn,
            },
            log_retention=_LOG_RETENTION,
            description="Block public access and restrict policies on exfiltrated S3 buckets",
        )
        Tags.of(self.s3_fn).add("Component", "s3-responder")

        # ------------------------------------------------------------------ #
        # EventBridge Rules — route HIGH/CRITICAL findings to responders      #
        # ------------------------------------------------------------------ #
        events.Rule(
            self,
            "EC2FindingsRule",
            rule_name="guardduty-ec2-findings",
            description="Route HIGH/CRITICAL EC2 GuardDuty findings to EC2 responder Lambda",
            event_pattern=events.EventPattern(
                source=["aws.guardduty"],
                detail_type=["GuardDuty Finding"],
                detail={
                    "severity": [{"numeric": [">=", 7.0]}],
                    "type": _ec2_type_filter(_EC2_FINDING_PREFIXES),
                },
            ),
            targets=[targets.LambdaFunction(self.ec2_fn)],
        )

        events.Rule(
            self,
            "IAMFindingsRule",
            rule_name="guardduty-iam-findings",
            description="Route HIGH/CRITICAL IAM GuardDuty findings to IAM responder Lambda",
            event_pattern=events.EventPattern(
                source=["aws.guardduty"],
                detail_type=["GuardDuty Finding"],
                detail={
                    "severity": [{"numeric": [">=", 7.0]}],
                    "type": _ec2_type_filter(_IAM_FINDING_PREFIXES),
                },
            ),
            targets=[targets.LambdaFunction(self.iam_fn)],
        )

        events.Rule(
            self,
            "S3FindingsRule",
            rule_name="guardduty-s3-findings",
            description="Route HIGH/CRITICAL S3 GuardDuty findings to S3 responder Lambda",
            event_pattern=events.EventPattern(
                source=["aws.guardduty"],
                detail_type=["GuardDuty Finding"],
                detail={
                    "severity": [{"numeric": [">=", 7.0]}],
                    "type": _ec2_type_filter(_S3_FINDING_PREFIXES),
                },
            ),
            targets=[targets.LambdaFunction(self.s3_fn)],
        )

        # All findings (any severity) → SNS for notification pipeline
        events.Rule(
            self,
            "AllFindingsRule",
            rule_name="guardduty-all-findings-notify",
            description="Route ALL GuardDuty findings (any severity) to SNS for notifications",
            event_pattern=events.EventPattern(
                source=["aws.guardduty"],
                detail_type=["GuardDuty Finding"],
            ),
            targets=[targets.SnsTopic(guardduty_stack.findings_topic)],
        )

        # ------------------------------------------------------------------ #
        # Outputs                                                             #
        # ------------------------------------------------------------------ #
        cdk.CfnOutput(
            self,
            "EC2ResponderArn",
            value=self.ec2_fn.function_arn,
            description="EC2 Responder Lambda ARN",
        )
        cdk.CfnOutput(
            self,
            "IAMResponderArn",
            value=self.iam_fn.function_arn,
            description="IAM Responder Lambda ARN",
        )
        cdk.CfnOutput(
            self,
            "S3ResponderArn",
            value=self.s3_fn.function_arn,
            description="S3 Responder Lambda ARN",
        )
