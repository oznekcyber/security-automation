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
docker build -t phase4-integration-hub .
docker run -p 8000:8000 --env-file .env phase4-integration-hub
```

Then open http://localhost:8000/docs for the interactive API documentation.

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SECRET_KEY` | JWT signing secret | Yes |
| `API_KEY` | Static API key for service accounts | No |
| `LOG_LEVEL` | Logging verbosity (default: INFO) | No |
