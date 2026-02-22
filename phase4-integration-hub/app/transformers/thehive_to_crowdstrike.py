"""Transform TheHive case updates back to CrowdStrike Falcon detection updates.

Design notes
------------
* TheHive is the analyst's workspace; analysts resolve, escalate and annotate cases
  there.  We push those decisions back to CrowdStrike so that Falcon's detection
  queue stays accurate and auditable.

* Status mapping is intentionally conservative: we only translate statuses we
  can positively map rather than silently dropping or mis-mapping unknown values.

* The detection_id must be recoverable from the TheHive case.  We look in two
  places: `sourceRef` (set by our outbound transformer) and `customFields`
  (in case the case was created manually but tagged with a CrowdStrike ref).
"""

from __future__ import annotations

from typing import Optional

from app.models.thehive import TheHiveWebhookPayload
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Status mapping
# ---------------------------------------------------------------------------

# TheHive case status → CrowdStrike detection status
# "Resolved" maps to "closed" because CrowdStrike's terminal state is "closed"
# "In Progress" maps to "in_progress" to keep the Falcon queue synchronized
# "New" maps to "new" – unlikely to be sent back but included for completeness
_STATUS_MAP: dict[str, str] = {
    "Resolved": "closed",
    "In Progress": "in_progress",
    "InProgress": "in_progress",
    "New": "new",
    "Open": "new",
}


def _map_thehive_status(thehive_status: str | None) -> str | None:
    """Map TheHive case status to its CrowdStrike equivalent.

    Returns None when the status has no meaningful CrowdStrike counterpart,
    signalling to callers that the status field should not be included in
    the PATCH payload.
    """
    if thehive_status is None:
        return None
    return _STATUS_MAP.get(thehive_status)


# ---------------------------------------------------------------------------
# Detection ID extraction
# ---------------------------------------------------------------------------

def extract_detection_id(case_data: dict) -> Optional[str]:
    """Extract a CrowdStrike detection_id from a TheHive case dict.

    Checks sourceRef first (populated by our outbound transformer), then
    customFields (for manually created or migrated cases).
    """
    # Primary path: sourceRef was set by transform_detection_to_alert
    source_ref = case_data.get("sourceRef", "")
    if source_ref and source_ref.startswith("ldt:"):
        # CrowdStrike detection IDs follow the pattern ldt:<cid>:<n>
        return source_ref

    # Fallback: analyst may have stored the ID in customFields
    custom_fields = case_data.get("customFields", {}) or {}
    crowdstrike_raw = custom_fields.get("crowdstrike_raw", {}) or {}
    detection_id = crowdstrike_raw.get("detection_id")
    if detection_id:
        return detection_id

    # Last resort: check for an explicit customField key
    return custom_fields.get("crowdstrike_detection_id")


# ---------------------------------------------------------------------------
# Public transformation function
# ---------------------------------------------------------------------------

def transform_case_update_to_crowdstrike(payload: TheHiveWebhookPayload) -> dict:
    """Convert a TheHive webhook case-update event into a CrowdStrike PATCH payload.

    Logs the before/after JSON for every transformation.

    Returns a dict suitable for passing to CrowdStrikeService.update_detection().
    Returns an empty dict when the case cannot be correlated to a CrowdStrike
    detection (caller should skip the update in that case).
    """
    before_json = payload.model_dump_json()

    case_data = payload.object or {}
    detection_id = extract_detection_id(case_data)

    if not detection_id:
        logger.warning(
            "no_crowdstrike_detection_id",
            object_id=payload.objectId,
            source_ref=case_data.get("sourceRef"),
        )
        return {}

    thehive_status = case_data.get("status")
    cs_status = _map_thehive_status(thehive_status)

    # Use the case summary as an analyst comment pushed back to CrowdStrike
    # so that investigation notes are visible to Falcon operators
    comment: Optional[str] = case_data.get("summary") or case_data.get("description")

    result: dict = {"detection_id": detection_id}
    if cs_status:
        result["status"] = cs_status
    if comment:
        result["comment"] = comment

    after_json = str(result)
    logger.info(
        "transformed_case_update_to_crowdstrike",
        detection_id=detection_id,
        thehive_status=thehive_status,
        cs_status=cs_status,
        has_comment=bool(comment),
        before=before_json,
        after=after_json,
    )
    return result
