# Phase 6 — AWS GuardDuty Automated Response System

A production-ready, event-driven security automation pipeline that detects
threats via **AWS GuardDuty** and automatically contains them using three
purpose-built **Lambda** responders — all deployed with **AWS CDK** (Python).

---

## Architecture

```
AWS GuardDuty
     │
     │  Finding (HIGH/CRITICAL severity)
     ▼
Amazon EventBridge
     ├────────────────────────────────────────────────────────────┐
     │  type: UnauthorizedAccess:EC2/*                            │
     │  type: Backdoor:EC2/*                                      │
     ▼                                                            │
┌─────────────────────┐                                           │
│  EC2 Responder λ    │  1. Replace SGs → Quarantine SG          │
│  guardduty-ec2-     │  2. EBS Snapshot (forensic)              │
│  responder          │  3. Tag instance (chain-of-custody)       │
│                     │  4. SSM memory collection (best-effort)   │
└──────────┬──────────┘                                           │
           │                           ┌──────────────────────────┘
           │                           │  type: UnauthorizedAccess:IAMUser/*
           │                           │  type: CredentialAccess:IAMUser/*
           │                           ▼
           │                ┌──────────────────────┐
           │                │  IAM Responder λ     │  1. Disable access key
           │                │  guardduty-iam-      │  2. Attach deny-all policy
           │                │  responder           │  3. CloudTrail audit lookup
           │                └──────────┬───────────┘
           │                           │
           │                           │  type: Policy:S3/*
           │                           │  type: Exfiltration:S3/*
           │                           ▼
           │                ┌──────────────────────┐
           │                │  S3 Responder λ      │  1. Block Public Access (all 4)
           │                │  guardduty-s3-       │  2. Restrictive bucket policy
           │                │  responder           │  3. CloudTrail S3 event lookup
           │                └──────────┬───────────┘
           │                           │
           └──────────────┬────────────┘
                          │ All responders notify:
                          ├──► TheHive  (create security case)
                          ├──► Splunk   (ship finding to HEC)
                          └──► Slack    (webhook notification)

ALL findings (any severity) ──► SNS Topic ──► Email / further integrations

CloudWatch Dashboard: finding volume, error rates, p99 response duration
CloudWatch Alarms:    error threshold breaches → SNS alert
```

---

## AWS Free Tier Cost Estimate

> GuardDuty offers a **30-day free trial** for all accounts. After the trial,
> costs depend on data volume. The rest of the stack uses Free Tier services.

| Service | Free Tier | Estimated Monthly (low volume) |
|---|---|---|
| **GuardDuty** | 30-day trial | ~$1–$5/month (small account) |
| **Lambda** | 1M requests, 400K GB-seconds | ~$0 (under 100K invocations/month) |
| **EventBridge** | 14M events | ~$0 |
| **SNS** | 1M publishes | ~$0 |
| **CloudWatch Logs** | 5 GB/month | ~$0–$0.50 |
| **CloudWatch Dashboard** | 3 free dashboards | ~$0 |
| **EBS Snapshots** | None | ~$0.05/GB/month |
| **Total** | | **~$2–$10/month** |

---

## GuardDuty 30-Day Free Trial

1. Open **AWS Console → GuardDuty → Get Started**
2. Click **Enable GuardDuty** — the 30-day trial starts immediately
3. GuardDuty analyzes VPC Flow Logs, CloudTrail, and DNS logs automatically
4. No additional data sources need to be enabled for the trial
5. The CDK stack will also create a detector programmatically via `CfnDetector`

To check trial status:
```bash
aws guardduty list-detectors --query 'DetectorIds[0]' --output text | \
  xargs -I{} aws guardduty get-free-trial-statistics --detector-id {}
```

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.11+ | `python3 --version` |
| AWS CDK | 2.100+ | `npm install -g aws-cdk` |
| Node.js | 18+ | Required by CDK |
| AWS CLI | 2.x | `aws --version` |
| boto3 | 1.34+ | Installed via requirements.txt |
| AWS Account | — | With `AdministratorAccess` for deployment |

---

## Quickstart Deployment (5 Steps)

### Step 1 — Clone and configure environment

```bash
cd phase6-aws-guardduty
cp .env.example .env
# Edit .env with your real values:
#   AWS_ACCOUNT_ID, AWS_REGION, SLACK_WEBHOOK_URL, etc.
```

### Step 2 — Install Python dependencies

```bash
pip install -r requirements.txt
# For CDK:
pip install -r cdk/requirements.txt
```

### Step 3 — Bootstrap CDK (one-time per account/region)

```bash
cd cdk/
export CDK_DEFAULT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
export CDK_DEFAULT_REGION=us-east-1
cdk bootstrap aws://$CDK_DEFAULT_ACCOUNT/$CDK_DEFAULT_REGION
```

### Step 4 — Deploy all stacks

```bash
# From the cdk/ directory:
cdk deploy --all --require-approval never
```

This deploys three CloudFormation stacks in order:
1. **GuardDutyStack** — Detector, quarantine SG, SNS topic
2. **LambdaStack** — Three Lambda functions + IAM roles + EventBridge rules
3. **MonitoringStack** — CloudWatch dashboard + alarms

### Step 5 — Verify deployment

```bash
# List deployed Lambda functions
aws lambda list-functions \
  --query 'Functions[?starts_with(FunctionName, `guardduty`)].FunctionName'

# Test the EC2 responder with a simulated finding
python simulator/finding_simulator.py --type ec2 --output event | \
  aws lambda invoke \
    --function-name guardduty-ec2-responder \
    --payload file:///dev/stdin \
    response.json && cat response.json
```

---

## Environment Variables Reference

All variables are defined in `.env.example`. Copy to `.env` and fill in your values.

| Variable | Required | Description |
|---|---|---|
| `AWS_REGION` | Yes | AWS region for all resources (e.g. `us-east-1`) |
| `AWS_ACCOUNT_ID` | Yes | Your 12-digit AWS account ID |
| `THEHIVE_URL` | No | TheHive 5 base URL (Phase 4 integration) |
| `THEHIVE_API_KEY` | No | TheHive Bearer API key |
| `SPLUNK_HEC_URL` | No | Splunk HEC endpoint URL (Phase 2 integration) |
| `SPLUNK_HEC_TOKEN` | No | Splunk HEC authentication token |
| `SLACK_WEBHOOK_URL` | No | Slack incoming webhook URL for alerts |
| `SNS_TOPIC_ARN` | Auto | Populated from CDK output after deploy |
| `QUARANTINE_SG_NAME` | Auto | Set by CDK (`guardduty-quarantine`) |
| `SSM_PARAMETER_PREFIX` | Auto | SSM path prefix (`/guardduty-response`) |
| `CDK_DEFAULT_ACCOUNT` | Yes | Account ID for CDK environment |
| `CDK_DEFAULT_REGION` | Yes | Region for CDK environment |

> **Note:** If `THEHIVE_URL`, `SPLUNK_HEC_URL`, or `SLACK_WEBHOOK_URL` are not
> set, those integrations are silently skipped. Lambda response actions
> (isolation, snapshot, policy changes) always execute regardless.

---

## Local Testing with moto

The test suite uses [moto](https://docs.getmoto.org/) to mock all AWS API calls.
No real AWS credentials or resources are needed.

### Install test dependencies

```bash
pip install -r requirements.txt
```

### Run all tests

```bash
cd phase6-aws-guardduty/
pytest tests/ -v
```

### Run a specific test module

```bash
pytest tests/test_ec2_responder.py -v
pytest tests/test_iam_responder.py -v
pytest tests/test_s3_responder.py -v
```

### Expected output

```
tests/test_ec2_responder.py::test_isolate_instance_replaces_security_groups PASSED
tests/test_ec2_responder.py::test_snapshot_volumes_creates_snapshots PASSED
tests/test_ec2_responder.py::test_tag_instance_applies_metadata PASSED
tests/test_ec2_responder.py::test_handler_end_to_end_success PASSED
tests/test_ec2_responder.py::test_handler_missing_instance_id PASSED
tests/test_ec2_responder.py::test_handler_quarantine_sg_not_found PASSED
tests/test_iam_responder.py::test_disable_access_key_deactivates_key PASSED
tests/test_iam_responder.py::test_attach_deny_all_policy PASSED
tests/test_iam_responder.py::test_handler_end_to_end_success PASSED
tests/test_iam_responder.py::test_handler_missing_access_key_details PASSED
tests/test_iam_responder.py::test_handler_direct_finding_no_envelope PASSED
tests/test_s3_responder.py::test_block_public_access_enables_all_settings PASSED
tests/test_s3_responder.py::test_apply_restrictive_policy PASSED
tests/test_s3_responder.py::test_handler_end_to_end_success PASSED
tests/test_s3_responder.py::test_handler_missing_bucket_name PASSED
tests/test_s3_responder.py::test_handler_direct_finding_no_envelope PASSED

16 passed in X.XXs
```

---

## Finding Simulator

Use `simulator/finding_simulator.py` to generate realistic GuardDuty finding
events for local handler testing without a live GuardDuty detector.

### Usage

```bash
# Generate an EC2 SSH brute-force finding (EventBridge event format)
python simulator/finding_simulator.py --type ec2 --output event

# Generate an IAM credential compromise finding (raw finding JSON)
python simulator/finding_simulator.py --type iam --output json

# Generate an S3 public access finding with custom severity
python simulator/finding_simulator.py --type s3 --output event --severity 9.0

# Pipe directly to a Lambda handler for local testing
python simulator/finding_simulator.py --type ec2 --output event > /tmp/test_event.json
```

### Simulator Options

| Flag | Values | Default | Description |
|---|---|---|---|
| `--type` | `ec2`, `iam`, `s3` | `ec2` | Finding type to generate |
| `--output` | `json`, `event` | `event` | Raw finding or EventBridge envelope |
| `--severity` | 1.0–9.0 | `8.0` | GuardDuty severity score |
| `--account-id` | 12-digit number | `123456789012` | AWS account ID to embed |
| `--region` | AWS region | `us-east-1` | AWS region to embed |

### Import as a module

```python
from simulator.finding_simulator import make_ec2_finding, wrap_eventbridge

finding = make_ec2_finding(severity=9.0, account_id="999999999999", region="eu-west-1")
event = wrap_eventbridge(finding)
```

---

## IAM Permissions Summary

All IAM roles follow least-privilege. Each permission is scoped to the minimum
resource set and includes a `StringEquals: aws:RequestedRegion` condition where
supported.

### EC2 Responder Role

| Permission | Resource | Reason |
|---|---|---|
| `ec2:DescribeInstances` | `*` | Look up current security groups on the target instance |
| `ec2:DescribeSecurityGroups` | `*` | Resolve quarantine SG name to ID |
| `ec2:ModifyInstanceAttribute` | `*` | Replace security groups with quarantine SG (containment) |
| `ec2:DescribeVolumes` | `*` | List volumes attached to the instance for snapshotting |
| `ec2:CreateSnapshot` | `*` | Create forensic EBS snapshots before instance termination |
| `ec2:CreateTags` | `*` | Tag instance and snapshots with forensic chain-of-custody metadata |
| `ssm:SendCommand` | `*` | Dispatch memory/artefact collection script to the instance |
| `ssm:GetCommandInvocation` | `*` | Poll SSM command execution status |
| `ssm:GetParameter` | `/guardduty-response/*` | Read runtime configuration from SSM Parameter Store |

> **Note on `*` resources for EC2 Describe operations:** AWS does not support
> resource-level restrictions for most EC2 Describe APIs. The `aws:RequestedRegion`
> condition limits scope to the deployment region.

### IAM Responder Role

| Permission | Resource | Reason |
|---|---|---|
| `iam:UpdateAccessKey` | `arn:aws:iam::*:user/*` | Disable the compromised access key (primary containment) |
| `iam:PutUserPolicy` | `arn:aws:iam::*:user/*` | Attach emergency deny-all inline policy (belt-and-suspenders) |
| `iam:ListAccessKeys` | `arn:aws:iam::*:user/*` | Enumerate all keys for the user to ensure full coverage |
| `iam:GetUser` | `arn:aws:iam::*:user/*` | Verify the user exists before attempting to disable |
| `cloudtrail:LookupEvents` | `*` | Fetch recent API activity for forensic context (no resource-level support) |
| `ssm:GetParameter` | `/guardduty-response/*` | Read runtime configuration from SSM Parameter Store |

### S3 Responder Role

| Permission | Resource | Reason |
|---|---|---|
| `s3:PutBucketPublicAccessBlock` | `arn:aws:s3:::*` | Enable all four Block Public Access settings (primary containment) |
| `s3:GetBucketPublicAccessBlock` | `arn:aws:s3:::*` | Read current state before modification |
| `s3:PutBucketPolicy` | `arn:aws:s3:::*` | Apply deny-external-principals bucket policy |
| `s3:GetBucketPolicy` | `arn:aws:s3:::*` | Read existing policy before replacement |
| `cloudtrail:LookupEvents` | `*` | Fetch recent S3 data events for forensic context |
| `ssm:GetParameter` | `/guardduty-response/*` | Read runtime configuration from SSM Parameter Store |

---

## Integration with Phase 2 (Splunk) and Phase 4 (TheHive)

This phase integrates seamlessly with the earlier pipeline phases.

### Phase 2 — Splunk Log Ingestion Pipeline

The `lambda/shared/splunk_client.py` module ships every GuardDuty finding to
the same Splunk HEC endpoint configured in Phase 2.

**Finding format in Splunk:**
- `sourcetype`: `aws:guardduty:finding`
- `source`: `aws:guardduty`
- `index`: `security`
- Extra fields: `_automated_actions` (list), `_pipeline_version` (phase6)

**Splunk search to view findings:**
```spl
index=security sourcetype="aws:guardduty:finding"
| eval severity=mvindex(split(tostring(severity), "."), 0)
| table _time, type, severity, accountId, region, _automated_actions
| sort -_time
```

### Phase 4 — TheHive SOAR Platform

The `lambda/shared/thehive_client.py` module creates a TheHive 5 case for every
GuardDuty finding processed by a responder Lambda.

**Case attributes set automatically:**
- `title`: `[GuardDuty] {finding_type} — Account {account_id}`
- `severity`: Mapped from GuardDuty (7-9 → High/3, 4-6 → Medium/2, 1-3 → Low/1)
- `tags`: `guardduty`, `finding-type:{type}`, `account:{id}`, `automated-response`
- `description`: Full finding JSON + automated actions taken
- `flag`: `true` (urgent)
- `tlp`: `2` (AMBER)

---

## CDK Stack Overview

### GuardDutyStack

- **`guardduty.CfnDetector`** — GuardDuty detector with S3 data event logging
- **`ec2.SecurityGroup` (quarantine)** — Deny-all SG: no inbound rules, `allow_all_outbound=False`
- **`sns.Topic`** — `guardduty-findings` topic; optional email subscription

**Outputs:** `DetectorId`, `QuarantineSGId`, `FindingsTopicArn`

### LambdaStack

- **3 Lambda functions** (EC2, IAM, S3) — Python 3.11, 256MB, 30s timeout
- **Lambda Layer** — Shared `thehive_client`, `splunk_client`, `slack_notifier`
- **3 least-privilege IAM roles** — One per responder
- **4 EventBridge rules** — EC2, IAM, S3 (HIGH/CRITICAL only) + All findings to SNS

**Finding type routing:**

| EventBridge Rule | Finding Prefixes Matched | Target |
|---|---|---|
| `guardduty-ec2-findings` | `UnauthorizedAccess:EC2/`, `Backdoor:EC2/`, `Trojan:EC2/` | EC2 Lambda |
| `guardduty-iam-findings` | `UnauthorizedAccess:IAMUser/`, `CredentialAccess:IAMUser/` | IAM Lambda |
| `guardduty-s3-findings` | `Policy:S3/`, `Exfiltration:S3/`, `Impact:S3/` | S3 Lambda |
| `guardduty-all-findings-notify` | All findings (any severity) | SNS topic |

### MonitoringStack

- **CloudWatch Dashboard** (`GuardDuty-Automated-Response`) — Invocations, errors, p99 duration
- **3 CloudWatch Alarms** — One per responder; triggers SNS on first error

---

## Directory Structure

```
phase6-aws-guardduty/
├── cdk/                          # AWS CDK infrastructure-as-code
│   ├── app.py                    # CDK app entry point
│   ├── requirements.txt          # CDK Python dependencies
│   └── stacks/
│       ├── guardduty_stack.py    # Detector, quarantine SG, SNS
│       ├── lambda_stack.py       # Lambda functions, IAM, EventBridge
│       └── monitoring_stack.py   # CloudWatch dashboards and alarms
├── lambda/
│   ├── ec2_responder/
│   │   └── handler.py            # Isolate, snapshot, tag, SSM collection
│   ├── iam_responder/
│   │   └── handler.py            # Disable key, deny-all policy, CloudTrail
│   ├── s3_responder/
│   │   └── handler.py            # Block public access, restrictive policy
│   └── shared/
│       ├── thehive_client.py     # Phase 4 TheHive integration
│       ├── splunk_client.py      # Phase 2 Splunk HEC integration
│       └── slack_notifier.py     # Slack webhook notifications
├── simulator/
│   └── finding_simulator.py      # Generate mock GuardDuty findings
├── tests/
│   ├── test_ec2_responder.py     # EC2 handler unit tests (moto)
│   ├── test_iam_responder.py     # IAM handler unit tests (moto)
│   └── test_s3_responder.py      # S3 handler unit tests (moto)
├── requirements.txt              # Project dependencies
├── .env.example                  # Environment variable template
├── .gitignore                    # Ignore .env, __pycache__, cdk.out
└── README.md                     # This file
```

---

## Teardown

```bash
cd cdk/
cdk destroy --all
```

> GuardDuty charges stop immediately when the detector is deleted.
> EBS snapshots created by forensic response must be deleted manually.

---

## Security Considerations

1. **Secrets management** — Store API keys in **AWS SSM Parameter Store** as
   `SecureString` parameters, not in environment variables or `.env`.

2. **Quarantine SG** — The deny-all SG has no rules. Instances moved to it lose
   all network connectivity immediately, which may cause service disruption.

3. **IAM deny-all policy** — The emergency lockout uses `Deny: *`. Ensure your
   break-glass procedure can remove this policy if needed.

4. **False positives** — GuardDuty can generate false positives. Consider a
   suppression list for known-good IPs before enabling in production.

5. **Forensic snapshots** — EBS snapshots contain potentially sensitive data.
   Ensure they are encrypted and access-controlled via IAM.

6. **CloudTrail data events** — S3 data events are only visible in CloudTrail
   if you have enabled S3 data event logging for your trail.

---

*Part of the Security Automation Pipeline — Phase 6 of 6.*
