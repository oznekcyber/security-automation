"""Async-safe circuit breaker implementation.

States
------
CLOSED   – Normal operation; failures are counted.
OPEN     – Circuit is tripped; calls fail immediately without reaching the backend.
HALF_OPEN – A limited probe is allowed to test whether the backend has recovered.

Transition rules
----------------
CLOSED → OPEN        when failure_count >= failure_threshold
OPEN   → HALF_OPEN   when now() - last_failure_time >= recovery_timeout
HALF_OPEN → CLOSED   on a successful probe call
HALF_OPEN → OPEN     on a failed probe call (reset last_failure_time)
"""

import asyncio
import time
from enum import Enum
from typing import Any, Callable

from app.utils.logger import get_logger

logger = get_logger(__name__)


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreakerOpenError(Exception):
    """Raised when a call is attempted while the circuit breaker is OPEN."""

    def __init__(self, name: str) -> None:
        super().__init__(f"Circuit breaker '{name}' is OPEN – call rejected")
        self.name = name


class CircuitBreaker:
    """Thread-safe (asyncio.Lock) circuit breaker for async functions.

    Args:
        name: Human-readable identifier used in logs and errors.
        failure_threshold: Number of consecutive failures that trip the circuit.
        recovery_timeout: Seconds to wait in OPEN state before probing (HALF_OPEN).
        half_open_max_calls: Number of probe calls allowed while HALF_OPEN.
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        half_open_max_calls: int = 1,
    ) -> None:
        self._name = name
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._half_open_max_calls = half_open_max_calls

        self._state: CircuitState = CircuitState.CLOSED
        self._failure_count: int = 0
        self._half_open_calls: int = 0
        self._last_failure_time: float = 0.0
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public read-only properties
    # ------------------------------------------------------------------

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def failure_count(self) -> int:
        return self._failure_count

    @property
    def last_failure_time(self) -> float:
        return self._last_failure_time

    # ------------------------------------------------------------------
    # Core call method
    # ------------------------------------------------------------------

    async def call(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """Execute *func* subject to circuit-breaker logic.

        Raises:
            CircuitBreakerOpenError: When state is OPEN and the recovery timeout
                has not yet elapsed.
            Exception: Any exception raised by *func* itself.
        """
        async with self._lock:
            await self._maybe_transition_to_half_open()

            if self._state == CircuitState.OPEN:
                logger.warning(
                    "circuit_breaker_rejected",
                    name=self._name,
                    state=self._state,
                )
                raise CircuitBreakerOpenError(self._name)

            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self._half_open_max_calls:
                    raise CircuitBreakerOpenError(self._name)
                self._half_open_calls += 1

        # Execute the function outside the lock so we don't block other callers
        try:
            result = await func(*args, **kwargs)
        except Exception as exc:
            async with self._lock:
                await self._on_failure()
            raise

        async with self._lock:
            await self._on_success()

        return result

    # ------------------------------------------------------------------
    # Internal state machine helpers  (must be called with _lock held)
    # ------------------------------------------------------------------

    async def _maybe_transition_to_half_open(self) -> None:
        if self._state == CircuitState.OPEN and self._last_failure_time > 0:
            elapsed = time.monotonic() - self._last_failure_time
            if elapsed >= self._recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
                logger.info(
                    "circuit_breaker_half_open",
                    name=self._name,
                    elapsed_seconds=round(elapsed, 1),
                )

    async def _on_success(self) -> None:
        if self._state in (CircuitState.HALF_OPEN, CircuitState.CLOSED):
            prev_state = self._state
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._half_open_calls = 0
            if prev_state == CircuitState.HALF_OPEN:
                logger.info("circuit_breaker_closed", name=self._name)

    async def _on_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = time.monotonic()

        if self._state == CircuitState.HALF_OPEN:
            # Failed probe → immediately reopen
            self._state = CircuitState.OPEN
            self._half_open_calls = 0
            logger.warning(
                "circuit_breaker_reopened",
                name=self._name,
                failure_count=self._failure_count,
            )
        elif self._failure_count >= self._failure_threshold:
            self._state = CircuitState.OPEN
            logger.warning(
                "circuit_breaker_opened",
                name=self._name,
                failure_count=self._failure_count,
                threshold=self._failure_threshold,
            )
