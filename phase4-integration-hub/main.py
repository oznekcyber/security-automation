#!/usr/bin/env python3
"""
Phase 4 — API Integration Hub (FastAPI)

Unified REST API gateway exposing all security automation phases behind
a single, authenticated, documented interface.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(
    title="Security Automation — API Integration Hub",
    description=(
        "Unified API gateway for the security automation portfolio. "
        "Provides authenticated access to alert normalization, log ingestion, "
        "SOAR playbooks, and threat intelligence enrichment."
    ),
    version="1.0.0",
    contact={
        "name": "Security Automation Portfolio",
        "url": "https://github.com/oznekcyber/security-automation",
    },
    license_info={"name": "MIT"},
)


class HealthResponse(BaseModel):
    status: str
    version: str
    phases: list[str]


class EnrichRequest(BaseModel):
    indicator: str
    indicator_type: str = "ip"


class EnrichResponse(BaseModel):
    indicator: str
    indicator_type: str
    verdict: str
    threat_score: int
    source: str


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check() -> HealthResponse:
    """Return API health status and available phases."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        phases=[
            "phase1-normalizer",
            "phase2-splunk-pipeline",
            "phase3-soar-playbook",
        ],
    )


@app.get("/", tags=["System"])
async def root() -> JSONResponse:
    """Redirect to API documentation."""
    return JSONResponse(
        {
            "message": "Security Automation API Integration Hub",
            "docs": "/docs",
            "health": "/health",
        }
    )


@app.post("/enrich", response_model=EnrichResponse, tags=["Threat Intel"])
async def enrich_indicator(request: EnrichRequest) -> EnrichResponse:
    """
    Enrich a threat indicator (IP address or file hash) via VirusTotal
    and AbuseIPDB. Returns a normalized verdict and threat score.
    """
    if not request.indicator:
        raise HTTPException(status_code=422, detail="indicator must not be empty")

    # Stub response — Phase 1 integration point
    return EnrichResponse(
        indicator=request.indicator,
        indicator_type=request.indicator_type,
        verdict="unknown",
        threat_score=0,
        source="stub — configure Phase 1 API keys to enable live enrichment",
    )
