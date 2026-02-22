"""Pydantic v2 models for TheHive 5 API payloads."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TheHiveArtifact(BaseModel):
    """Observable / artifact attached to a TheHive alert or case."""

    dataType: str  # e.g. "hash", "ip", "domain", "filename"
    data: str
    message: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class TheHiveAlert(BaseModel):
    """Alert payload sent to TheHive POST /api/v1/alert."""

    title: str
    description: str
    # TheHive severity: 1=Low, 2=Medium, 3=High, 4=Critical
    severity: int = Field(default=2, ge=1, le=4)
    source: str
    sourceRef: str
    type: str = "alert"
    tags: List[str] = Field(default_factory=list)
    # TLP: 0=WHITE, 1=GREEN, 2=AMBER, 3=RED
    tlp: int = Field(default=2, ge=0, le=3)
    # PAP: 0=WHITE, 1=GREEN, 2=AMBER, 3=RED
    pap: int = Field(default=2, ge=0, le=3)
    customFields: Dict[str, Any] = Field(default_factory=dict)
    artifacts: List[TheHiveArtifact] = Field(default_factory=list)


class TheHiveCase(BaseModel):
    """Case payload for TheHive POST /api/v1/case."""

    title: str
    description: str
    severity: int = Field(default=2, ge=1, le=4)
    startDate: Optional[int] = None  # epoch millis
    owner: Optional[str] = None
    flag: bool = False
    tlp: int = Field(default=2, ge=0, le=3)
    tags: List[str] = Field(default_factory=list)
    status: str = "New"
    customFields: Dict[str, Any] = Field(default_factory=dict)


class TheHiveWebhookPayload(BaseModel):
    """Outer envelope for events delivered by TheHive webhooks."""

    operation: Optional[str] = None  # e.g. "Update", "Create"
    objectType: Optional[str] = None  # e.g. "Case", "Alert"
    objectId: Optional[str] = None
    object: Optional[Dict[str, Any]] = None
    details: Optional[Dict[str, Any]] = None
    # Raw metadata the TheHive webhook infrastructure may include
    metadata: Optional[Dict[str, Any]] = None


class TheHiveCaseUpdate(BaseModel):
    """Partial case update payload for PATCH /api/v1/case/{id}."""

    status: Optional[str] = None
    resolution: Optional[str] = None
    summary: Optional[str] = None
    tags: Optional[List[str]] = None
    customFields: Optional[Dict[str, Any]] = None


class SyncStatus(BaseModel):
    """Snapshot of the integration hub's synchronisation state."""

    last_crowdstrike_sync: Optional[str] = None  # ISO-8601 timestamp
    last_thehive_sync: Optional[str] = None
    crowdstrike_to_thehive_count: int = 0
    thehive_to_crowdstrike_count: int = 0
    errors: List[str] = Field(default_factory=list)
    circuit_breaker_state: Dict[str, str] = Field(default_factory=dict)
