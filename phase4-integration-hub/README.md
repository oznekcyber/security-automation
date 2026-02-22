# Phase 4 — API Integration Hub (FastAPI)

A FastAPI-based integration hub that exposes a unified REST API across all
security automation phases, with OpenAPI documentation and JWT authentication.

## Features
- Unified REST API for all phases
- JWT-based authentication
- OpenAPI/Swagger UI documentation
- Rate limiting and request logging
- Health check and metrics endpoints

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
