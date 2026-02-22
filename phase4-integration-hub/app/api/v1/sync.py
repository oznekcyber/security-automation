"""Sync management endpoints."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Request

from app.models.thehive import SyncStatus
from app.utils.logger import get_logger

router = APIRouter()
logger = get_logger(__name__)


@router.get("/status", response_model=SyncStatus, summary="Sync status")
async def sync_status(request: Request) -> SyncStatus:
    """Return the current synchronisation statistics and circuit breaker states."""
    sync_manager = getattr(request.app.state, "sync_manager", None)
    if sync_manager is None:
        return SyncStatus()
    return sync_manager.get_status()


@router.post("/manual", summary="Trigger manual sync")
async def manual_sync(request: Request) -> Dict[str, Any]:
    """Trigger an immediate CrowdStrike → TheHive synchronisation.

    Uses mock data when ``CROWDSTRIKE_MOCK=true`` so this endpoint is safe to
    call in development without live credentials.
    """
    sync_manager = getattr(request.app.state, "sync_manager", None)
    if sync_manager is None:
        return {"error": "Sync manager not initialised"}

    logger.info("manual_sync_triggered")
    result = await sync_manager.sync_crowdstrike_to_thehive()
    return {"result": result, "status": sync_manager.get_status().model_dump()}
