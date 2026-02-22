"""
GuardDuty Stack — CDK stack that provisions:
  - GuardDuty detector
  - Quarantine security group (deny-all in + out)
  - EventBridge rules to route findings to Lambda handlers
  - SNS topic for notifications

All resources follow least-privilege IAM and are tagged for cost tracking.
"""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import (
    Stack,
    Tags,
    aws_guardduty as guardduty,
    aws_ec2 as ec2,
    aws_sns as sns,
    aws_sns_subscriptions as subscriptions,
    aws_events as events,
    aws_events_targets as targets,
    aws_lambda as lambda_,
)
from constructs import Construct


class GuardDutyStack(Stack):
    """
    Core infrastructure stack: GuardDuty detector, quarantine SG,
    EventBridge rules, and SNS notification topic.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        notification_email: str | None = None,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ------------------------------------------------------------------ #
        # 1. GuardDuty Detector                                               #
        # ------------------------------------------------------------------ #
        self.detector = guardduty.CfnDetector(
            self,
            "GuardDutyDetector",
            enable=True,
            finding_publishing_frequency="SIX_HOURS",
            # S3 data events and EKS audit logs add cost — enable selectively
            data_sources=guardduty.CfnDetector.CFNDataSourceConfigurationsProperty(
                s3_logs=guardduty.CfnDetector.CFNS3LogsConfigurationProperty(enable=True),
            ),
        )
        Tags.of(self.detector).add("Project", "guardduty-response")
        Tags.of(self.detector).add("Phase", "6")

        # ------------------------------------------------------------------ #
        # 2. VPC + Quarantine Security Group                                  #
        # ------------------------------------------------------------------ #
        # Look up the default VPC — in production, use a dedicated VPC
        self.vpc = ec2.Vpc.from_lookup(self, "DefaultVPC", is_default=True)

        self.quarantine_sg = ec2.SecurityGroup(
            self,
            "QuarantineSG",
            vpc=self.vpc,
            security_group_name="guardduty-quarantine",
            description="GuardDuty quarantine — deny ALL inbound and outbound traffic",
            allow_all_outbound=False,  # No outbound rules added
        )
        # No inbound rules added — all traffic is implicitly denied
        Tags.of(self.quarantine_sg).add("Purpose", "guardduty-quarantine")

        # ------------------------------------------------------------------ #
        # 3. SNS Topic for Notifications                                       #
        # ------------------------------------------------------------------ #
        self.findings_topic = sns.Topic(
            self,
            "GuardDutyFindingsTopic",
            topic_name="guardduty-findings",
            display_name="GuardDuty Findings Notifications",
        )
        if notification_email:
            self.findings_topic.add_subscription(
                subscriptions.EmailSubscription(notification_email)
            )

        # ------------------------------------------------------------------ #
        # 4. Public outputs                                                   #
        # ------------------------------------------------------------------ #
        cdk.CfnOutput(
            self,
            "DetectorId",
            value=self.detector.ref,
            description="GuardDuty Detector ID",
        )
        cdk.CfnOutput(
            self,
            "QuarantineSGId",
            value=self.quarantine_sg.security_group_id,
            description="Quarantine Security Group ID",
        )
        cdk.CfnOutput(
            self,
            "FindingsTopicArn",
            value=self.findings_topic.topic_arn,
            description="SNS topic ARN for GuardDuty findings",
        )
