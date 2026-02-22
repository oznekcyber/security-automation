# Security Alert Normalizer

**Phase 1 of the Security Automation Engineer Learning Roadmap**

A production-quality Python tool that fetches threat intelligence from
[VirusTotal](https://www.virustotal.com) and [AbuseIPDB](https://www.abuseipdb.com),
normalizes the vendor-specific JSON responses into a unified schema, and
optionally ships the results to a webhook endpoint.

---

## Why this exists

Every security tool speaks a different JSON dialect.  CrowdStrike, SentinelOne,
VirusTotal, and AbuseIPDB all return different field names, nesting structures,
and scoring conventions for the same underlying concept — "how dangerous is this
IP/file?"

A SOAR platform needs one consistent schema to feed its playbooks, and that
normalization work falls squarely on the Security Automation Engineer.  This
tool demonstrates the full pattern:

```
[Threat Intel APIs] → [Collectors] → [Normalizer] → [Unified Schema] → [Webhook / SIEM]
```

---

## Architecture

```
security-alert-normalizer/
├── src/
│   ├── collectors/
│   │   ├── virustotal.py    # VT v3 API client (IPs + file hashes)
│   │   └── abuseipdb.py     # AbuseIPDB v2 API client (IPs only)
│   ├── transformers/
│   │   ├── schema.py        # NormalizedAlert dataclass — the unified schema
│   │   └── normalizer.py    # Vendor response → NormalizedAlert + jq filtering
│   ├── outputs/
│   │   └── webhook.py       # POST alerts to a webhook endpoint
│   └── utils/
│       ├── config.py        # .env / environment variable loader
│       └── logger.py        # Structured logging setup
├── tests/
│   └── test_normalizer.py   # 37 pytest unit tests (no API calls required)
├── main.py                  # CLI entry point
├── requirements.txt
└── .env.example
```

### Design decisions

**Why dataclasses, not TypedDict or Pydantic?**  
Standard library dataclasses give us type hints, `asdict()` for free JSON
serialization, and no external dependency for the schema definition itself.
Pydantic would be a sensible upgrade if this grew into a full service.

**Why jq via the Python `jq` library?**  
SOAR engineers use jq filters in playbook actions constantly.  Implementing
the filtering layer with the real `jq` binary (via the Python binding) means
the filter expressions you write here translate directly to Shuffle/XSOAR
workflow syntax.

**Threat score formula**  
- **VirusTotal**: `round((malicious + suspicious) / total_engines * 100)`, capped at 100.  
  Strong negative reputation (< -20) floors the score at 30.
- **AbuseIPDB**: `abuseConfidenceScore` (already 0-100 per their API spec).

**Verdict thresholds** (matches common SOC SOP):

| Score | Verdict    |
|-------|------------|
| ≥ 70  | malicious  |
| ≥ 30  | suspicious |
| > 0   | suspicious |
| 0     | clean      |
| no data | unknown  |

---

## Quickstart

### 1. Clone and install

```bash
git clone https://github.com/oznekcyber/Security-Alert-Normalizer.git
cd Security-Alert-Normalizer
pip install -r requirements.txt
```

### 2. Configure API keys

```bash
cp .env.example .env
# Edit .env and add your VirusTotal and AbuseIPDB API keys
```

Get free API keys at:
- VirusTotal: <https://www.virustotal.com/gui/join-us>
- AbuseIPDB: <https://www.abuseipdb.com/register>

### 3. Try the demo (no API keys needed)

```bash
python main.py --demo
```

This runs the full pipeline against built-in mock data that mirrors real
API responses.

---

## Usage

```
python main.py [--ips IP [IP ...]] [--hashes HASH [HASH ...]]
               [--output FILE] [--webhook URL] [--jq EXPR]
               [--demo] [--log-level {DEBUG,INFO,WARNING,ERROR}]
               [--log-file FILE]
```

### Examples

```bash
# Enrich IPs with both VirusTotal and AbuseIPDB
python main.py --ips 185.220.101.1 8.8.8.8

# Enrich file hashes (VirusTotal only — AbuseIPDB doesn't support hashes)
python main.py --hashes 44d88612fea8a8f36de82e1278abb02f

# Save to a custom file and POST to a webhook
python main.py --ips 45.33.32.156 \
               --output results.json \
               --webhook https://webhook.site/your-uuid

# Apply a jq filter to pull out only malicious alerts
python main.py --ips 185.220.101.1 \
               --jq '[.[] | select(.verdict == "malicious") | {ip: .indicator_value, score: .threat_score}]'

# Mix IPs and hashes, verbose logging
python main.py --ips 1.1.1.1 --hashes 44d88612fea8a8f36de82e1278abb02f \
               --log-level DEBUG

# Demo mode with a jq filter
python main.py --demo \
               --jq '[.[] | select(.source == "abuseipdb") | .geo]'
```

---

## Normalized Alert Schema

Every alert — regardless of whether it came from VirusTotal or AbuseIPDB —
is transformed into this structure:

```json
{
  "alert_id": "3f2d1a8e-...",
  "timestamp": "2024-02-19T12:00:00+00:00",
  "source": "virustotal",
  "indicator_type": "ip",
  "indicator_value": "185.220.101.1",
  "threat_score": 93,
  "verdict": "malicious",
  "tags": ["tor", "proxy"],
  "categories": ["proxy avoidance and anonymizers", "tor"],
  "geo": {
    "country": "DE",
    "country_code": "DE",
    "asn": 205100,
    "as_owner": "F3 Netze e.V.",
    "isp": null,
    "network": "185.220.101.0/24"
  },
  "analysis_stats": {
    "malicious": 67,
    "suspicious": 0,
    "harmless": 0,
    "undetected": 5,
    "timeout": 0
  },
  "abuse_confidence_score": 0,
  "total_abuse_reports": 0,
  "last_analysis_date": "2024-02-18T00:00:00+00:00",
  "collection_timestamp": "2024-02-19T12:00:00+00:00"
}
```

---

## Webhook delivery

Pass `--webhook <url>` to POST the normalized alert payload to any HTTP
endpoint that accepts JSON.  [Webhook.site](https://webhook.site) provides
a free disposable endpoint perfect for testing.

The payload envelope looks like:

```json
{
  "schema_version": "1.0",
  "alert_count": 3,
  "alerts": [ ... ]
}
```

---

## Running tests

```bash
pytest tests/ -v
```

37 unit tests covering:
- Schema field defaults and serialization
- VirusTotal normalizer (malicious/clean/empty/edge cases)
- AbuseIPDB normalizer (malicious/clean/empty/edge cases)
- jq filter application
- Threat score capping at 100

---

## Environment variables

| Variable              | Required | Default                   | Description                        |
|-----------------------|----------|---------------------------|------------------------------------|
| `VIRUSTOTAL_API_KEY`  | Yes      | —                         | VirusTotal v3 API key              |
| `ABUSEIPDB_API_KEY`   | Yes      | —                         | AbuseIPDB v2 API key               |
| `WEBHOOK_URL`         | No       | `""`                      | Webhook endpoint for alert delivery |
| `REQUEST_TIMEOUT`     | No       | `30`                      | HTTP timeout in seconds            |
| `MAX_RETRIES`         | No       | `3`                       | Retry attempts on transient failures |
| `RETRY_BACKOFF_FACTOR`| No       | `1.5`                     | Exponential back-off multiplier    |
| `OUTPUT_FILE`         | No       | `normalized_alerts.json`  | Default output file path           |

---

## Error handling

The tool handles real-world failure scenarios gracefully:

| Scenario               | Behaviour                                           |
|------------------------|-----------------------------------------------------|
| Invalid API key        | `PermissionError` logged; indicator skipped         |
| Rate limit (HTTP 429)  | Sleeps per `Retry-After` header; retries up to `MAX_RETRIES` times |
| Network timeout        | Logged as warning; indicator skipped                |
| Malformed JSON         | `ValueError` logged; indicator skipped              |
| Indicator not in DB (404) | Logged as info; no alert produced              |
| Invalid jq expression  | Warning logged; rest of pipeline continues          |

---

## Skills demonstrated

- JSON schema design and normalization across heterogeneous APIs
- VirusTotal v3 and AbuseIPDB v2 REST API integration
- API key authentication and HTTP client best practices
- Exponential back-off and rate-limit handling
- jq-style filtering via the Python `jq` library
- Webhook delivery with retry logic
- Structured logging
- Type hints and docstrings throughout
- 37 offline unit tests with pytest
- `.env`-based configuration management
