"""TheHive 5 service — wraps the TheHive REST API with circuit breaker + retry."""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

import httpx

from app.models.thehive import TheHiveAlert, TheHiveCase, TheHiveCaseUpdate
from app.utils.circuit_breaker import CircuitBreaker
from app.utils.logger import get_logger
from app.utils.retry import retry_with_backoff

logger = get_logger(__name__)


class TheHiveService:
    """Async client for TheHive 5 REST API."""

    def __init__(self) -> None:
        self._base_url = os.getenv("THEHIVE_URL", "http://localhost:9000")
        self._api_key = os.getenv("THEHIVE_API_KEY", "")
        self._http = httpx.AsyncClient(timeout=30.0)
        self._circuit_breaker = CircuitBreaker(
            name="thehive",
            failure_threshold=int(os.getenv("CIRCUIT_BREAKER_THRESHOLD", "5")),
            recovery_timeout=float(os.getenv("CIRCUIT_BREAKER_TIMEOUT", "60")),
        )

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    @retry_with_backoff(max_retries=3, backoff_factor=2.0, exceptions=(httpx.HTTPError,))
    async def create_alert(self, alert: TheHiveAlert) -> Dict[str, Any]:
        """Create a new alert in TheHive."""

        async def _do_create() -> Dict[str, Any]:
            resp = await self._http.post(
                f"{self._base_url}/api/v1/alert",
                content=alert.model_dump_json(),
                headers=self._headers(),
            )
            resp.raise_for_status()
            data = resp.json()
            logger.info("thehive_alert_created", alert_id=data.get("_id"), source_ref=alert.sourceRef)
            return data

        return await self._circuit_breaker.call(_do_create)

    # ------------------------------------------------------------------
    # Cases
    # ------------------------------------------------------------------

    @retry_with_backoff(max_retries=3, backoff_factor=2.0, exceptions=(httpx.HTTPError,))
    async def create_case(self, case: TheHiveCase) -> Dict[str, Any]:
        """Create a new case in TheHive."""

        async def _do_create() -> Dict[str, Any]:
            resp = await self._http.post(
                f"{self._base_url}/api/v1/case",
                content=case.model_dump_json(),
                headers=self._headers(),
            )
            resp.raise_for_status()
            data = resp.json()
            logger.info("thehive_case_created", case_id=data.get("_id"))
            return data

        return await self._circuit_breaker.call(_do_create)

    @retry_with_backoff(max_retries=3, backoff_factor=2.0, exceptions=(httpx.HTTPError,))
    async def update_case(self, case_id: str, update: TheHiveCaseUpdate) -> Dict[str, Any]:
        """Partially update an existing TheHive case."""

        async def _do_update() -> Dict[str, Any]:
            # Exclude unset fields so we don't accidentally overwrite with None
            payload = update.model_dump(exclude_none=True)
            resp = await self._http.patch(
                f"{self._base_url}/api/v1/case/{case_id}",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

        return await self._circuit_breaker.call(_do_update)

    @retry_with_backoff(max_retries=3, backoff_factor=2.0, exceptions=(httpx.HTTPError,))
    async def get_case(self, case_id: str) -> Dict[str, Any]:
        """Retrieve a TheHive case by ID."""

        async def _do_get() -> Dict[str, Any]:
            resp = await self._http.get(
                f"{self._base_url}/api/v1/case/{case_id}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

        return await self._circuit_breaker.call(_do_get)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Release the underlying httpx client."""
        await self._http.aclose()

    @property
    def circuit_breaker_state(self) -> str:
        return self._circuit_breaker.state.value
