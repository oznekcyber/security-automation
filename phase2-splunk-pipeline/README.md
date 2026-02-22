# Phase 2 — Splunk Log Ingestion Pipeline

A Splunk HTTP Event Collector (HEC) ingestion pipeline that parses, enriches,
and forwards security log events in real time.

## Features
- Structured log parsing (syslog, CEF, LEEF)
- Splunk HEC forwarding with retry logic
- Field normalization to CIM (Common Information Model)
- Configurable via environment variables

## Quick Start

```bash
docker build -t phase2-splunk-pipeline .
docker run --env-file .env phase2-splunk-pipeline
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SPLUNK_HEC_URL` | Splunk HEC endpoint URL | Yes |
| `SPLUNK_HEC_TOKEN` | Splunk HEC token | Yes |
| `LOG_LEVEL` | Logging verbosity (default: INFO) | No |
