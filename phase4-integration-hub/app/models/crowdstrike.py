"""Pydantic v2 models for CrowdStrike Falcon API payloads."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class CrowdStrikeParentDetails(BaseModel):
    parent_process_id: Optional[int] = None
    parent_process_graph_id: Optional[str] = None
    parent_cmdline: Optional[str] = None
    parent_image_file_name: Optional[str] = None


class CrowdStrikeBehavior(BaseModel):
    behavior_id: str
    tactic: Optional[str] = None
    tactic_id: Optional[str] = None
    technique: Optional[str] = None
    technique_id: Optional[str] = None
    objective: Optional[str] = None
    severity: Optional[int] = None
    confidence: Optional[int] = None
    description: Optional[str] = None
    filename: Optional[str] = None
    filepath: Optional[str] = None
    cmdline: Optional[str] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    parent_details: Optional[CrowdStrikeParentDetails] = None


class CrowdStrikeDevice(BaseModel):
    device_id: str
    hostname: Optional[str] = None
    local_ip: Optional[str] = None
    external_ip: Optional[str] = None
    mac_address: Optional[str] = None
    os_version: Optional[str] = None
    platform_name: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    agent_version: Optional[str] = None


class CrowdStrikeDetection(BaseModel):
    detection_id: str
    cid: Optional[str] = None
    created_timestamp: Optional[str] = None
    max_severity: int = 0
    max_severity_displayname: Optional[str] = None
    status: Optional[str] = "new"
    behaviors: List[CrowdStrikeBehavior] = Field(default_factory=list)
    device: Optional[CrowdStrikeDevice] = None

    # Top-level convenience fields (may duplicate behavior data for the "worst" behavior)
    filename: Optional[str] = None
    filepath: Optional[str] = None
    cmdline: Optional[str] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    tactic: Optional[str] = None
    technique: Optional[str] = None
    objective: Optional[str] = None
    parent_details: Optional[CrowdStrikeParentDetails] = None


class CrowdStrikeWebhookPayload(BaseModel):
    """Outer envelope for CrowdStrike streaming event / webhook deliveries."""

    event_type: Optional[str] = None
    detection: Optional[CrowdStrikeDetection] = None
    # Raw metadata included by CrowdStrike webhook infrastructure
    metadata: Optional[Dict[str, Any]] = None


class CrowdStrikeSyncResponse(BaseModel):
    """Response envelope returned by our sync endpoints for CrowdStrike operations."""

    success: bool
    detection_ids_processed: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    message: Optional[str] = None
