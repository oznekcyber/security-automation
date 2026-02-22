# Phase 3 — SOAR Incident Response Playbook

Automated incident response playbooks integrated with Shuffle SOAR.
Orchestrates alert triage, enrichment, containment, and notification workflows.

## Features
- Automated alert triage with configurable severity thresholds
- Integration with VirusTotal, AbuseIPDB, and Shodan for enrichment
- Slack and email notification channels
- Evidence collection and ticket creation (Jira/ServiceNow)

## Quick Start

```bash
docker build -t phase3-soar-playbook .
docker run --env-file .env phase3-soar-playbook
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SHUFFLE_URL` | Shuffle SOAR API URL | Yes |
| `SHUFFLE_API_KEY` | Shuffle API key | Yes |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook | No |
