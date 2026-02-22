"""Webhook endpoints — receive events from CrowdStrike and TheHive."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status

from app.models.crowdstrike import CrowdStrikeWebhookPayload
from app.models.thehive import TheHiveWebhookPayload
from app.transformers.crowdstrike_to_thehive import transform_detection_to_alert
from app.utils.logger import get_logger

router = APIRouter()
logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Background task helpers
# ---------------------------------------------------------------------------


async def _process_thehive_event(payload: TheHiveWebhookPayload, request: Request) -> None:
    """Transform TheHive case update and push changes to CrowdStrike."""
    sync_manager = getattr(request.app.state, "sync_manager", None)
    if sync_manager is None:
        logger.error("sync_manager_not_initialized")
        return
    try:
        await sync_manager.sync_thehive_to_crowdstrike(payload)
    except Exception as exc:
        logger.error("thehive_webhook_processing_error", error=str(exc))


async def _process_crowdstrike_event(
    payload: CrowdStrikeWebhookPayload, request: Request
) -> None:
    """Transform CrowdStrike detection and create a TheHive alert."""
    sync_manager = getattr(request.app.state, "sync_manager", None)
    if sync_manager is None:
        logger.error("sync_manager_not_initialized")
        return
    if payload.detection is None:
        logger.warning("crowdstrike_webhook_no_detection")
        return
    try:
        alert = transform_detection_to_alert(payload.detection)
        await sync_manager.thehive.create_alert(alert)
        logger.info(
            "crowdstrike_webhook_alert_created",
            detection_id=payload.detection.detection_id,
        )
    except Exception as exc:
        logger.error("crowdstrike_webhook_processing_error", error=str(exc))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/thehive",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receive TheHive webhook",
)
async def thehive_webhook(
    payload: TheHiveWebhookPayload,
    background_tasks: BackgroundTasks,
    request: Request,
):
    """Accept an incoming TheHive webhook event.

    The payload is validated synchronously; the actual processing (transform +
    CrowdStrike update) is dispatched as a background task so the caller receives
    an immediate 202 Accepted response.
    """
    logger.info(
        "thehive_webhook_received",
        operation=payload.operation,
        object_type=payload.objectType,
        object_id=payload.objectId,
    )
    background_tasks.add_task(_process_thehive_event, payload, request)
    return {"accepted": True, "object_id": payload.objectId}


@router.post(
    "/crowdstrike",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receive CrowdStrike webhook",
)
async def crowdstrike_webhook(
    payload: CrowdStrikeWebhookPayload,
    background_tasks: BackgroundTasks,
    request: Request,
):
    """Accept an incoming CrowdStrike streaming event / webhook.

    The payload is validated synchronously; creating the TheHive alert is
    dispatched as a background task so the caller receives an immediate 202.
    """
    detection_id = payload.detection.detection_id if payload.detection else None
    logger.info(
        "crowdstrike_webhook_received",
        event_type=payload.event_type,
        detection_id=detection_id,
    )
    background_tasks.add_task(_process_crowdstrike_event, payload, request)
    return {"accepted": True, "detection_id": detection_id}
