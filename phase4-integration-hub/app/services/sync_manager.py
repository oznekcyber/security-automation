"""Orchestrates bidirectional sync between CrowdStrike and TheHive."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from app.models.thehive import SyncStatus, TheHiveWebhookPayload
from app.services.crowdstrike import CrowdStrikeService
from app.services.thehive import TheHiveService
from app.transformers.crowdstrike_to_thehive import transform_detections_batch
from app.transformers.thehive_to_crowdstrike import transform_case_update_to_crowdstrike
from app.utils.logger import get_logger

logger = get_logger(__name__)


class SyncManager:
    """Coordinates CrowdStrike ↔ TheHive data flow and tracks sync statistics."""

    def __init__(
        self,
        crowdstrike: CrowdStrikeService | None = None,
        thehive: TheHiveService | None = None,
    ) -> None:
        self.crowdstrike = crowdstrike or CrowdStrikeService()
        self.thehive = thehive or TheHiveService()

        self._cs_to_hive_count: int = 0
        self._hive_to_cs_count: int = 0
        self._last_cs_sync: str | None = None
        self._last_hive_sync: str | None = None
        self._errors: List[str] = []

    # ------------------------------------------------------------------
    # CrowdStrike → TheHive
    # ------------------------------------------------------------------

    async def sync_crowdstrike_to_thehive(self, limit: int = 10) -> Dict[str, Any]:
        """Poll CrowdStrike for new detections and create TheHive alerts.

        Returns a summary dict with processed count and any errors.
        """
        logger.info("sync_cs_to_hive_start", limit=limit)
        errors: List[str] = []
        processed: List[str] = []

        try:
            detections = await self.crowdstrike.get_detections(limit=limit)
        except Exception as exc:
            msg = f"Failed to fetch CrowdStrike detections: {exc}"
            logger.error("sync_cs_fetch_error", error=str(exc))
            self._errors.append(msg)
            return {"processed": [], "errors": [msg]}

        alerts = transform_detections_batch(detections)

        for alert in alerts:
            try:
                await self.thehive.create_alert(alert)
                processed.append(alert.sourceRef)
                self._cs_to_hive_count += 1
            except Exception as exc:
                msg = f"Failed to create TheHive alert for {alert.sourceRef}: {exc}"
                logger.error("sync_create_alert_error", source_ref=alert.sourceRef, error=str(exc))
                errors.append(msg)
                self._errors.append(msg)

        self._last_cs_sync = datetime.now(timezone.utc).isoformat()
        logger.info(
            "sync_cs_to_hive_complete",
            processed_count=len(processed),
            error_count=len(errors),
        )
        return {"processed": processed, "errors": errors}

    # ------------------------------------------------------------------
    # TheHive → CrowdStrike
    # ------------------------------------------------------------------

    async def sync_thehive_to_crowdstrike(self, payload: TheHiveWebhookPayload) -> Dict[str, Any]:
        """Process a TheHive case-update webhook and push the update to CrowdStrike."""
        logger.info(
            "sync_hive_to_cs_start",
            object_type=payload.objectType,
            object_id=payload.objectId,
        )

        update_dict = transform_case_update_to_crowdstrike(payload)
        if not update_dict:
            return {"skipped": True, "reason": "No CrowdStrike detection ID found in case"}

        detection_id = update_dict.get("detection_id")
        status = update_dict.get("status")
        comment = update_dict.get("comment")

        try:
            await self.crowdstrike.update_detection(
                detection_id=detection_id,
                status=status,
                comment=comment,
            )
            self._hive_to_cs_count += 1
            self._last_hive_sync = datetime.now(timezone.utc).isoformat()
            return {"updated": detection_id, "status": status}
        except Exception as exc:
            msg = f"Failed to update CrowdStrike detection {detection_id}: {exc}"
            logger.error("sync_cs_update_error", detection_id=detection_id, error=str(exc))
            self._errors.append(msg)
            return {"error": msg}

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> SyncStatus:
        """Return a snapshot of the current sync state."""
        return SyncStatus(
            last_crowdstrike_sync=self._last_cs_sync,
            last_thehive_sync=self._last_hive_sync,
            crowdstrike_to_thehive_count=self._cs_to_hive_count,
            thehive_to_crowdstrike_count=self._hive_to_cs_count,
            errors=list(self._errors[-50:]),  # cap at 50 most recent errors
            circuit_breaker_state={
                "crowdstrike": self.crowdstrike.circuit_breaker_state,
                "thehive": self.thehive.circuit_breaker_state,
            },
        )

    async def close(self) -> None:
        await self.crowdstrike.close()
        await self.thehive.close()
