"""
Monitoring Stack — CDK stack that provisions CloudWatch dashboards and alarms.

Dashboard shows:
  - Finding volume by type and severity over time
  - Automated response success/failure rates
  - Mean time to automated containment (Lambda duration as proxy)
"""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import (
    Duration,
    Stack,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_sns as sns,
)
from constructs import Construct

from stacks.lambda_stack import LambdaStack
from stacks.guardduty_stack import GuardDutyStack


class MonitoringStack(Stack):
    """CloudWatch dashboards and alarms for the GuardDuty response pipeline."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        lambda_stack: LambdaStack,
        guardduty_stack: GuardDutyStack,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        ec2_fn = lambda_stack.ec2_fn
        iam_fn = lambda_stack.iam_fn
        s3_fn = lambda_stack.s3_fn

        # ------------------------------------------------------------------ #
        # Metrics                                                             #
        # ------------------------------------------------------------------ #
        def invocations(fn: cdk.aws_lambda.Function) -> cloudwatch.Metric:
            return fn.metric_invocations(period=Duration.minutes(5))

        def errors(fn: cdk.aws_lambda.Function) -> cloudwatch.Metric:
            return fn.metric_errors(period=Duration.minutes(5))

        def duration(fn: cdk.aws_lambda.Function) -> cloudwatch.Metric:
            return fn.metric_duration(period=Duration.minutes(5), statistic="p99")

        # ------------------------------------------------------------------ #
        # Dashboard                                                           #
        # ------------------------------------------------------------------ #
        dashboard = cloudwatch.Dashboard(
            self,
            "GuardDutyDashboard",
            dashboard_name="GuardDuty-Automated-Response",
            period_override=cloudwatch.PeriodOverride.AUTO,
        )

        # Row 1: Invocations (finding volume by responder)
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Finding Volume — Invocations per Responder",
                left=[invocations(ec2_fn), invocations(iam_fn), invocations(s3_fn)],
                width=12,
                period=Duration.minutes(5),
            ),
            cloudwatch.GraphWidget(
                title="Response Errors per Responder",
                left=[errors(ec2_fn), errors(iam_fn), errors(s3_fn)],
                width=12,
                period=Duration.minutes(5),
            ),
        )

        # Row 2: Duration (proxy for MTTC — mean time to containment)
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Response Duration p99 (ms) — Mean Time to Containment Proxy",
                left=[duration(ec2_fn), duration(iam_fn), duration(s3_fn)],
                width=12,
                period=Duration.minutes(5),
            ),
            cloudwatch.SingleValueWidget(
                title="Total Automated Responses (24h)",
                metrics=[
                    ec2_fn.metric_invocations(period=Duration.hours(24), statistic="Sum"),
                    iam_fn.metric_invocations(period=Duration.hours(24), statistic="Sum"),
                    s3_fn.metric_invocations(period=Duration.hours(24), statistic="Sum"),
                ],
                width=12,
            ),
        )

        # ------------------------------------------------------------------ #
        # Alarms                                                              #
        # ------------------------------------------------------------------ #
        alarm_topic = guardduty_stack.findings_topic

        for fn, name in [(ec2_fn, "EC2"), (iam_fn, "IAM"), (s3_fn, "S3")]:
            alarm = cloudwatch.Alarm(
                self,
                f"{name}ResponderErrorAlarm",
                alarm_name=f"guardduty-{name.lower()}-responder-errors",
                alarm_description=f"GuardDuty {name} responder Lambda is erroring",
                metric=fn.metric_errors(period=Duration.minutes(5)),
                threshold=1,
                evaluation_periods=1,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            )
            alarm.add_alarm_action(cw_actions.SnsAction(alarm_topic))

        cdk.CfnOutput(
            self,
            "DashboardUrl",
            value=f"https://{self.region}.console.aws.amazon.com/cloudwatch/home#dashboards:name=GuardDuty-Automated-Response",
            description="CloudWatch Dashboard URL",
        )
