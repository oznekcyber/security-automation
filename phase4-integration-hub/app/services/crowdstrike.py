"""CrowdStrike Falcon service — wraps the Falcon REST API with circuit breaker + retry."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import httpx

from app.models.crowdstrike import CrowdStrikeDetection
from app.utils.circuit_breaker import CircuitBreaker
from app.utils.logger import get_logger
from app.utils.retry import retry_with_backoff

logger = get_logger(__name__)

_MOCK_MODE = os.getenv("CROWDSTRIKE_MOCK", "true").lower() in ("true", "1", "yes")


class CrowdStrikeService:
    """Async client for the CrowdStrike Falcon Detections API.

    When ``CROWDSTRIKE_MOCK=true`` (the default), all methods return data from
    the ``mocks/crowdstrike_responses.py`` module so that the hub can be developed
    and tested without live Falcon credentials.
    """

    def __init__(self) -> None:
        self._base_url = os.getenv("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")
        self._client_id = os.getenv("CROWDSTRIKE_CLIENT_ID", "")
        self._client_secret = os.getenv("CROWDSTRIKE_CLIENT_SECRET", "")
        self._mock = _MOCK_MODE
        self._access_token: Optional[str] = None
        self._http = httpx.AsyncClient(timeout=30.0)
        self._circuit_breaker = CircuitBreaker(
            name="crowdstrike",
            failure_threshold=int(os.getenv("CIRCUIT_BREAKER_THRESHOLD", "5")),
            recovery_timeout=float(os.getenv("CIRCUIT_BREAKER_TIMEOUT", "60")),
        )

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    @retry_with_backoff(max_retries=3, backoff_factor=2.0, exceptions=(httpx.HTTPError,))
    async def authenticate(self) -> str:
        """Obtain an OAuth2 access token via client credentials flow."""
        if self._mock:
            self._access_token = "mock_token"
            return "mock_token"

        async def _do_auth() -> str:
            resp = await self._http.post(
                f"{self._base_url}/oauth2/token",
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            token = resp.json()["access_token"]
            self._access_token = token
            return token

        return await self._circuit_breaker.call(_do_auth)

    # ------------------------------------------------------------------
    # Detections
    # ------------------------------------------------------------------

    @retry_with_backoff(max_retries=3, backoff_factor=2.0, exceptions=(httpx.HTTPError,))
    async def get_detections(
        self,
        limit: int = 10,
        offset: int = 0,
        filter: Optional[str] = None,
    ) -> List[CrowdStrikeDetection]:
        """Fetch detections from CrowdStrike (or mock data).

        The real API requires two calls: first to query detection IDs, then to
        fetch entity summaries.  In mock mode both calls are bypassed.
        """
        if self._mock:
            from mocks.crowdstrike_responses import get_mock_detections

            raw = get_mock_detections(limit=limit)
            return [CrowdStrikeDetection(**d) for d in raw]

        if not self._access_token:
            await self.authenticate()

        async def _do_get() -> List[CrowdStrikeDetection]:
            headers = {"Authorization": f"Bearer {self._access_token}"}
            params: Dict[str, Any] = {"limit": limit, "offset": offset}
            if filter:
                params["filter"] = filter

            # Step 1: query for detection IDs
            ids_resp = await self._http.get(
                f"{self._base_url}/detections/queries/detections/v1",
                params=params,
                headers=headers,
            )
            ids_resp.raise_for_status()
            detection_ids: List[str] = ids_resp.json().get("resources", [])
            if not detection_ids:
                return []

            # Step 2: fetch full entity summaries
            summaries_resp = await self._http.post(
                f"{self._base_url}/detections/entities/summaries/v1",
                json={"ids": detection_ids},
                headers=headers,
            )
            summaries_resp.raise_for_status()
            resources = summaries_resp.json().get("resources", [])
            return [CrowdStrikeDetection(**r) for r in resources]

        return await self._circuit_breaker.call(_do_get)

    @retry_with_backoff(max_retries=3, backoff_factor=2.0, exceptions=(httpx.HTTPError,))
    async def update_detection(
        self,
        detection_id: str,
        status: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> bool:
        """Update a detection's status and/or add an analyst comment."""
        if self._mock:
            logger.info(
                "mock_update_detection",
                detection_id=detection_id,
                status=status,
                comment=comment,
            )
            return True

        if not self._access_token:
            await self.authenticate()

        async def _do_update() -> bool:
            headers = {"Authorization": f"Bearer {self._access_token}"}
            payload: Dict[str, Any] = {"ids": [detection_id]}
            if status:
                payload["status"] = status
            if comment:
                payload["comment"] = comment

            resp = await self._http.patch(
                f"{self._base_url}/detections/entities/detections/v1",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
            return True

        return await self._circuit_breaker.call(_do_update)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Release the underlying httpx client."""
        await self._http.aclose()

    @property
    def circuit_breaker_state(self) -> str:
        return self._circuit_breaker.state.value
