# Phase 2 – Splunk SIEM Log Ingestion & Alerting Pipeline

A production-quality Python project that generates realistic security telemetry, ships it to **Splunk** via the HTTP Event Collector (HEC), and bundles a full set of saved searches, alert actions, and a SimpleXML dashboard.

Part of the **Security Automation Portfolio**:

| Phase | Description |
|-------|-------------|
| **1** | Threat-intel normalizer (VirusTotal + AbuseIPDB) |
| **2** | ← *This project* – Splunk SIEM ingestion pipeline |
| **3** | SOAR playbook automation |
| **4** | Integration hub |
| **5** | CI/CD hardening |
| **6** | AWS GuardDuty integration |

---

## Overview

The pipeline does three things:

1. **Generate** – five event generators produce realistic mock security telemetry:
   - SSH brute-force / suspicious logins (CEF + JSON)
   - Suspicious process execution (Mimikatz, PsExec, encoded PowerShell) with MITRE ATT&CK IDs
   - Suspicious outbound network connections with C2 beaconing patterns
   - DGA / DNS-tunnel query events
   - File-hash IOC matches (AV/EDR telemetry)

2. **Ship** – a `HECShipper` class sends events to Splunk with:
   - Correct `Authorization: Splunk <token>` header
   - Exponential back-off retry on HTTP 429 / 5xx
   - Separate shipper log file for HEC audit trails
   - A `BatchManager` that buffers and group-flushes for efficiency

3. **Integrate** – a `NormalizerBridge` transforms Phase 1 `NormalizedAlert` dicts into Splunk events with enriched fields (`severity`, `is_malicious`, `geo_country`, `indicator_family`, …).

---

## Prerequisites

- Python **3.9+**
- A running **Splunk Enterprise** instance (≥ 8.2) or **Splunk Cloud** account
- Network access from your workstation to the Splunk HEC endpoint (default port **8088**)

---

## Splunk Setup

### 1 – Enable the HTTP Event Collector

1. In Splunk Web go to **Settings → Data Inputs → HTTP Event Collector**.
2. Click **Global Settings** and set **Enable SSL** as required.  For local dev you can use plain HTTP on port 8088.
3. Click **New Token** and fill in:
   - **Name**: `phase2-pipeline`
   - **Source type**: Leave as default (sourcetype is set per-event by the shipper).
   - **Index**: `security_events` (create it first – see below).
4. Copy the generated token; you will paste it into `.env`.

### 2 – Create Indexes

In Splunk Web go to **Settings → Indexes → New Index** and create:

| Index name | Type | Max size |
|------------|------|----------|
| `security_events` | Events | 5 GB |
| `threat_intel` | Events | 2 GB |

### 3 – Source Types

The shipper sets sourcetypes per-event.  No manual sourcetype configuration is required unless you want custom field extractions.  The sourcetypes used are:

| Sourcetype | Description |
|------------|-------------|
| `syslog:ssh` | SSH authentication events |
| `syslog:process` | Process execution events |
| `network:flow` | Outbound connection / flow records |
| `network:dns` | DNS query events |
| `endpoint:ioc` | File-hash IOC detections |
| `threat:normalizer` | Phase 1 normalizer output |

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

```ini
# Splunk HEC endpoint – use https:// for production
SPLUNK_URL=http://localhost:8088

# Token from the HEC token creation step above
HEC_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Splunk indexes
INDEX_NAME=security_events
NORMALIZER_INDEX=threat_intel

# Batching / retry
BATCH_SIZE=100
MAX_RETRIES=3
RETRY_BACKOFF_FACTOR=1.5

# Logging
LOG_LEVEL=INFO
SHIPPER_LOG_FILE=shipper.log
```

---

## Installation

```bash
cd phase2-splunk-pipeline
pip install -r requirements.txt
```

---

## Usage

### Generate events and print to stdout (no Splunk required)

```bash
python main.py --generate-only 10
```

Prints 60 JSON records (10 of each event type) to stdout. Useful for inspecting the schema or piping into `jq`.

### Ship events to Splunk

```bash
python main.py --ship 20
```

Generates 20 events of each type (120 total) and ships them to Splunk via HEC in batches of `BATCH_SIZE`.

### Dry-run (skip actual HTTP calls)

```bash
python main.py --ship 10 --demo
```

Logs what would be sent without making any network requests.

### Ingest Phase 1 normalizer output

```bash
python main.py --ingest-normalizer /path/to/normalizer_output.json
```

Accepts a JSON array **or** newline-delimited JSON (NDJSON) file of Phase 1 `NormalizedAlert` dicts, transforms them, and ships to the `threat_intel` index.

### Override sourcetype

```bash
python main.py --ship 5 --sourcetype custom:syslog
```

### Continuous mode (Ctrl-C to stop)

```bash
python main.py --continuous
```

Generates one event of each type every 5 seconds – useful for populating real-time dashboards.

---

## Importing Splunk Configuration

### Saved Searches & Alerts

Copy the configuration files into your Splunk app:

```bash
# Replace <app> with your app name (e.g. "search")
cp splunk/savedsearches.conf $SPLUNK_HOME/etc/apps/<app>/local/
cp splunk/alerts.conf        $SPLUNK_HOME/etc/apps/<app>/local/

# Restart Splunk to pick up the changes
$SPLUNK_HOME/bin/splunk restart
```

Or import via **Splunk Web**: Settings → Searches, reports, and alerts → Import.

### Dashboard

1. Go to **Search & Reporting** → **Dashboards** → **Create New Dashboard**.
2. Choose **Classic Dashboard (XML)**, click **Edit Source**.
3. Paste the contents of `splunk/dashboard.xml` and click **Save**.

---

## Project Structure

```
phase2-splunk-pipeline/
├── src/
│   ├── generators/
│   │   ├── ssh_events.py       # SSH auth events (CEF + JSON)
│   │   ├── process_events.py   # Suspicious process execution
│   │   ├── network_events.py   # C2 beaconing, DNS tunnelling
│   │   └── ioc_events.py       # File-hash AV/EDR detections
│   ├── shippers/
│   │   ├── hec_shipper.py      # HEC HTTP client with retry
│   │   └── batch_manager.py    # Buffered batch sender
│   ├── integrations/
│   │   └── normalizer_bridge.py  # Phase 1 → Splunk transform
│   └── utils/
│       ├── config.py           # Environment-variable config loader
│       └── logger.py           # Dual-stream logging setup
├── splunk/
│   ├── savedsearches.conf      # 6 SPL detection searches
│   ├── alerts.conf             # Email + webhook alert actions
│   └── dashboard.xml           # SimpleXML operations dashboard
├── tests/
│   └── test_generators.py      # 34 offline unit tests
├── main.py                     # CLI entry point
├── requirements.txt
├── .env.example
└── README.md
```

---

## Running Tests

```bash
cd phase2-splunk-pipeline
python -m pytest tests/ -v
```

Expected output: **34 passed**.  All tests are fully offline – no Splunk instance is required.

```
tests/test_generators.py::TestSSHFailedLogin::test_brute_force_burst_same_ip PASSED
tests/test_generators.py::TestNetworkEvents::test_beaconing_pattern_low_cv PASSED
tests/test_generators.py::TestIOCEvents::test_hash_lengths PASSED
... (34 total)
```

---

## Detection Logic – Threshold Rationale

| Search | Threshold | Rationale |
|--------|-----------|-----------|
| SSH Brute Force | 5 failures / 60 s | Catches real attacks; below human retry noise |
| Rare Process | ≤ 3 hosts | LOLBin / novel malware rarely spreads instantly |
| C2 Beaconing | CV < 0.3, ≥ 5 connections | Mechanical regularity; humans browse irregularly |
| IOC Match | Any critical-severity match | Zero tolerance for known-bad malware |
| DNS Suspicious | Any DGA / tunnel query | Legitimate software doesn't use DGA domains |

---

## Security Notes

- **Never commit a real `HEC_TOKEN`** to version control.  `.env` is in `.gitignore` by design (add it if not already present).
- The HEC shipper sets `verify=False` by default to support self-signed certificates in development.  In production set `verify=True` (or pass the CA bundle path) and use HTTPS.
- Saved search alert emails reference `soc-team@example.com` – replace with real distribution lists before deploying.
