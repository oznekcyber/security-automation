#!/usr/bin/env python3
"""
AWS GuardDuty Automated Response — CDK Application Entry Point.

Deploy with:
    cd cdk/
    pip install -r requirements.txt
    cdk bootstrap aws://ACCOUNT-ID/us-east-1
    cdk deploy --all

Or deploy a single stack:
    cdk deploy GuardDutyStack
"""

import os
import aws_cdk as cdk
from dotenv import load_dotenv

# Load .env from the project root if present
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from stacks.guardduty_stack import GuardDutyStack
from stacks.lambda_stack import LambdaStack
from stacks.monitoring_stack import MonitoringStack

app = cdk.App()

env = cdk.Environment(
    account=os.environ.get("CDK_DEFAULT_ACCOUNT") or os.environ.get("AWS_ACCOUNT_ID", ""),
    region=os.environ.get("CDK_DEFAULT_REGION") or os.environ.get("AWS_REGION", "us-east-1"),
)

notification_email = os.environ.get("NOTIFICATION_EMAIL")

guardduty_stack = GuardDutyStack(
    app,
    "GuardDutyStack",
    notification_email=notification_email,
    env=env,
    description="Phase 6 — GuardDuty detector, quarantine SG, SNS topic",
)

lambda_stack = LambdaStack(
    app,
    "LambdaStack",
    guardduty_stack=guardduty_stack,
    env=env,
    description="Phase 6 — GuardDuty Lambda response handlers",
)
lambda_stack.add_dependency(guardduty_stack)

monitoring_stack = MonitoringStack(
    app,
    "MonitoringStack",
    lambda_stack=lambda_stack,
    guardduty_stack=guardduty_stack,
    env=env,
    description="Phase 6 — CloudWatch dashboards and alarms",
)
monitoring_stack.add_dependency(lambda_stack)

app.synth()
