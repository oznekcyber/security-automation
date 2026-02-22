"""Health check endpoint."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/health", summary="Health check")
async def health(request: Request) -> Dict[str, Any]:
    """Return application health, service versions, and circuit breaker states."""
    sync_manager = getattr(request.app.state, "sync_manager", None)

    cb_states: Dict[str, str] = {}
    if sync_manager:
        status = sync_manager.get_status()
        cb_states = status.circuit_breaker_state

    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
        "services": {
            "crowdstrike": {"version": "falcon-api-v2", "circuit_breaker": cb_states.get("crowdstrike", "CLOSED")},
            "thehive": {"version": "thehive5", "circuit_breaker": cb_states.get("thehive", "CLOSED")},
        },
    }
