# Phase 3 — SOAR Incident Response Playbook

> **Security Automation Portfolio · Phase 3 of 6**
>
> Phase 1: Security Alert Normalizer (VirusTotal / AbuseIPDB)  
> Phase 2: Splunk Log Ingestion Pipeline with Detections  
> **Phase 3 (this): SOAR Automation Layer — automated incident response**

This project demonstrates a production-style SOAR (Security Orchestration,
Automation and Response) pipeline built on **Shuffle SOAR**, **TheHive**, and
**Cortex**. A Splunk alert fires a webhook → Shuffle runs the playbook → IOCs
are extracted and enriched → a risk score drives triage → a structured TheHive
case is created → analysts are notified in Slack → the result is logged back to
Splunk via HEC.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Project Structure](#project-structure)
3. [Quick Start (Docker)](#quick-start-docker)
4. [Python Helper Scripts](#python-helper-scripts)
5. [Enrichment Scoring Logic](#enrichment-scoring-logic)
6. [Shuffle Workflow](#shuffle-workflow)
7. [TheHive Case Templates](#thehive-case-templates)
8. [Simulating an Alert End-to-End](#simulating-an-alert-end-to-end)
9. [Running Tests](#running-tests)
10. [Environment Variables](#environment-variables)
11. [Security Notes](#security-notes)

---

## Architecture Overview

```
Splunk Alert
     │
     ▼
Shuffle SOAR Webhook
     │
     ├─▶ ioc_extractor.py      Extract IPs, URLs, hashes, emails
     │
     ├─▶ VirusTotal API         Enrich each IOC
     ├─▶ AbuseIPDB API
     │
     ├─▶ enrichment_scorer.py   Composite 0–10 risk score + reasoning
     │
     ├─▶ Decision Branch
     │       ├─ score > 5  →  auto-escalate
     │       ├─ score 2–5  →  analyst review queue
     │       └─ score < 2  →  auto-close + log
     │
     ├─▶ thehive_case_builder.py  Build structured TheHive case
     ├─▶ TheHive API              Create case + observables
     │
     ├─▶ slack_formatter.py       Build Block Kit Slack message
     ├─▶ Slack Webhook            Notify #soc-alerts channel
     │
     └─▶ Splunk HEC               Log full workflow result
```

---

## Project Structure

```
soar-incident-response/
├── shuffle/
│   ├── workflows/
│   │   └── phishing_response.json   Shuffle workflow definition
│   └── app_configs/
│       ├── virustotal.json          VT v3 app configuration
│       └── abuseipdb.json           AbuseIPDB v2 app configuration
├── src/
│   ├── ioc_extractor.py             IOC extraction (stdlib only)
│   ├── enrichment_scorer.py         Composite risk scorer
│   ├── thehive_case_builder.py      TheHive v4 case payload builder
│   └── slack_formatter.py           Slack Block Kit formatter
├── thehive/
│   └── case_templates/
│       ├── phishing.json            Phishing investigation template
│       ├── malware.json             Malware detection template
│       └── network_anomaly.json     Suspicious network activity template
├── docker-compose.yml               Full SOAR stack (Shuffle + TheHive + Cortex)
├── simulate_alert.py                Mock Splunk alert simulator
├── tests/
│   ├── test_ioc_extractor.py        27 unit tests for IOC extraction
│   ├── test_enrichment_scorer.py    26 unit tests for risk scoring
│   └── test_case_builder.py         16 unit tests for case building
├── requirements.txt
├── .env.example
└── .gitignore
```

---

## Quick Start (Docker)

### Prerequisites
- Docker ≥ 24 and Docker Compose v2
- At least 8 GB RAM (Cassandra + Elasticsearch are memory-hungry)

### 1. Clone and configure

```bash
cd phase3-soar-playbook/soar-incident-response
cp .env.example .env
# Edit .env — add your API keys
```

### 2. Spin up the full SOAR stack

```bash
docker-compose up -d
```

This starts:
| Service | URL | Default credentials |
|---------|-----|---------------------|
| Shuffle SOAR | http://localhost:3001 | admin / changeme123! |
| TheHive | http://localhost:9000 | admin@thehive.local / changeme123! |
| Cortex | http://localhost:9001 | admin / changeme123! |

### 3. Import the Shuffle workflow

1. Open http://localhost:3001 and log in
2. Navigate to **Workflows → Import**
3. Upload `shuffle/workflows/phishing_response.json`
4. Configure your API keys in the workflow's app credentials panel

### 4. Import TheHive case templates

```bash
# Using TheHive API (once the stack is running)
for template in thehive/case_templates/*.json; do
  curl -s -u admin@thehive.local:secret \
    -H "Content-Type: application/json" \
    -d @"$template" \
    http://localhost:9000/api/case/template
done
```

### 5. Fire a test alert

```bash
python simulate_alert.py --url http://localhost:3001/api/v1/hooks/YOUR_WEBHOOK_ID
```

---

## Python Helper Scripts

All scripts are self-contained and testable standalone.

### `src/ioc_extractor.py`

Extracts and validates IOCs from raw alert text using only Python stdlib.

**Input:** raw text string (Splunk alert body, email body, log line, etc.)

**Output:**
```json
{
  "ips":    ["185.220.101.42"],
  "urls":   ["http://malicious-domain.ru/payload.exe"],
  "hashes": [{"value": "44d88612fea8a8f36de82e1278abb02f", "type": "md5"}],
  "emails": ["attacker@evil.example"]
}
```

Key decisions:
- RFC-1918 / loopback / documentation ranges are **excluded** — they waste
  API quota and are never useful for external enrichment
- Results are **deduplicated** before returning
- Hashes are **lower-cased** for consistent downstream lookup

```bash
# Test standalone
python -c "
from src.ioc_extractor import IOCExtractor
e = IOCExtractor()
print(e.extract('traffic from 185.220.101.42 to http://evil.ru hash 44d88612fea8a8f36de82e1278abb02f'))
"
```

---

### `src/enrichment_scorer.py`

Combines VirusTotal and AbuseIPDB results into a single 0–10 risk score.

**Input:**
```python
{
    "vt_result":    {"malicious": 52, "suspicious": 3, "total": 75, "reputation": -60},
    "abuse_result": {"confidence": 87, "total_reports": 312}
}
```

**Output:**
```python
{
    "score":    8.4,
    "tier":     "CRITICAL",
    "decision": "auto-escalate",
    "breakdown": {
        "vt_detection_ratio": {"raw": 0.693, "weighted": 2.77, "reasoning": "..."},
        "vt_reputation":      {"raw": -60,   "weighted": 1.20, "reasoning": "..."},
        "abuse_confidence":   {"raw": 87,    "weighted": 2.61, "reasoning": "..."},
        "report_volume":      {"raw": 312,   "weighted": 0.10, "reasoning": "..."},
    },
    "data_sources_used": ["virustotal", "abuseipdb"]
}
```

---

### `src/thehive_case_builder.py`

Builds a TheHive v4 REST API case payload from normalised enrichment data.

**Input:** dict with `alert_type`, `iocs`, `score_result`, `raw_alert` keys

**Output:** `{"case": {...}, "observables": [...]}`  — ready for TheHive API

---

### `src/slack_formatter.py`

Builds a Slack Block Kit message payload for the SOC channel.

**Output:** `{"blocks": [...], "attachments": [...]}`  — ready for Slack
Incoming Webhooks API

Color-coding:
- `danger` (red) for CRITICAL / HIGH
- `warning` (yellow) for MEDIUM
- `good` (green) for LOW / INFO

---

## Enrichment Scoring Logic

The scorer weights four independent signals to produce a 0–10 score:

| Signal | Weight | Rationale |
|--------|--------|-----------|
| VT malicious detection ratio | **40%** | Strongest signal — fraction of AV engines flagging an IOC |
| VT community reputation | **20%** | Captures historical analyst votes; negative = known bad |
| AbuseIPDB confidence | **30%** | IP-specific signal; lower false-positive rate for infrastructure |
| AbuseIPDB report volume | **10%** | Corroborates confidence; high volume = not a one-off |

Decision tiers match common SOC SOP:

| Score | Tier | Action |
|-------|------|--------|
| > 7 | CRITICAL | Auto-escalate; page on-call; P1 TheHive case |
| 5–7 | HIGH | Auto-escalate; P2 TheHive case |
| 3–5 | MEDIUM | Queue for analyst review |
| 1–3 | LOW | Analyst review; lower priority |
| < 1 | INFO | Auto-close; log only |

The scorer **degrades gracefully** — if AbuseIPDB is unavailable, the VT
signals are re-weighted across the remaining 70%, not discarded.

---

## Shuffle Workflow

`shuffle/workflows/phishing_response.json` defines a 9-node workflow:

```
[Webhook Trigger]
       │
[Extract IOCs]
       │
[Enrich via VT] ──── [Enrich via AbuseIPDB]
       │                       │
       └──────────┬────────────┘
                  │
         [Score Enrichment]
                  │
         [Decision Branch]
          /        |        \
  score>5       score 2-5   score<2
  [Auto-      [Analyst     [Auto-
  Escalate]    Review]      Close]
       │
[Create TheHive Case]
       │
[Slack Notification]
       │
[Log to Splunk HEC]
```

To import: **Shuffle UI → Workflows → Import →** upload the JSON file, then
configure API credentials in each app's settings panel.

---

## TheHive Case Templates

Three templates in `thehive/case_templates/`:

| Template | Severity | Tasks |
|----------|----------|-------|
| `phishing.json` | HIGH (3) | 9 investigation tasks |
| `malware.json` | HIGH (3) | 8 investigation tasks |
| `network_anomaly.json` | MEDIUM (2) | 7 investigation tasks |

Each template includes MITRE ATT&CK technique tags, TLP:AMBER, PAP:AMBER
defaults, and custom fields for source system and playbook version.

---

## Simulating an Alert End-to-End

`simulate_alert.py` fires realistic mock Splunk alert payloads with **fake
but plausible IOCs** — no real malicious data is used anywhere.

```bash
# Default: fires phishing alert to localhost:3001 webhook
python simulate_alert.py

# Target a specific Shuffle webhook
python simulate_alert.py --url http://localhost:3001/api/v1/hooks/ABC123

# Choose scenario: phishing | malware | network
python simulate_alert.py --scenario malware

# List available scenarios
python simulate_alert.py --list
```

The script prints a colour-coded summary of what was sent and the HTTP
response received from Shuffle.

---

## Running Tests

```bash
cd soar-incident-response
pip install -r requirements.txt
pytest tests/ -v
```

All 69 tests run entirely **offline** — no API keys or network access required.

```
tests/test_ioc_extractor.py   27 tests  (IP, URL, hash, email extraction)
tests/test_enrichment_scorer.py 26 tests  (scoring, tiers, partial data)
tests/test_case_builder.py    16 tests  (severity mapping, observables)
──────────────────────────────────────────
69 passed in 0.06s
```

---

## Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```bash
# Threat intelligence APIs
VIRUSTOTAL_API_KEY=your_vt_key
ABUSEIPDB_API_KEY=your_abuseipdb_key

# TheHive
THEHIVE_URL=http://localhost:9000
THEHIVE_API_KEY=your_thehive_api_key

# Slack
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...

# Splunk HEC
SPLUNK_HEC_URL=https://splunk:8088
SPLUNK_HEC_TOKEN=your_hec_token

# Shuffle SOAR
SHUFFLE_WEBHOOK_URL=http://localhost:3001/api/v1/hooks/YOUR_WEBHOOK_ID
```

---

## Security Notes

- **No secrets are hardcoded** anywhere in this project — all credentials
  are loaded from environment variables or `.env` files
- The `.env` file is excluded from git via `.gitignore`
- Fake IOCs used in tests and simulation are either RFC-5737 documentation
  addresses or clearly fictional domains (`example-malware.test`) that
  cannot resolve to real infrastructure
- All Python helper scripts validate/sanitize inputs before processing
