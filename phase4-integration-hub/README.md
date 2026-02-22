# Security Tool Integration Hub (Phase 4)

Bidirectional API middleware between **CrowdStrike Falcon** and **TheHive 5**.

## Architecture

```
CrowdStrike Falcon <---------------------------------------------> TheHive 5
        |                                                               |
        |  webhook / poll                             webhook / API    |
        v                                                               v
 +-----------------------------------------------------------------------+
 |                    Security Integration Hub                           |
 |                                                                       |
 |  /api/v1/webhooks/crowdstrike    /api/v1/webhooks/thehive            |
 |  /api/v1/sync/manual             /api/v1/sync/status                 |
 |  /api/v1/health                                                       |
 |                                                                       |
 |  CrowdStrikeService --transformer--> TheHiveService                  |
 |  TheHiveService     --transformer--> CrowdStrikeService               |
 |                                                                       |
 |  CircuitBreaker   RetryWithBackoff   StructuredLogging                |
 +-----------------------------------------------------------------------+
```

## Quick Start

```bash
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
# open http://localhost:8000/docs
```

## Running Tests

```bash
pytest tests/ -v
```

## Severity Mapping

| CrowdStrike (1-100) | TheHive |
|---|---|
| 1-25 | 1 Low |
| 26-50 | 2 Medium |
| 51-74 | 3 High |
| 75-100 | 4 Critical |

## Status Mapping

| TheHive Case Status | CrowdStrike Detection Status |
|---|---|
| Resolved | closed |
| In Progress | in_progress |
| New | new |
