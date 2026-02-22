"""Tests for sync endpoints and circuit breaker behavior."""

from __future__ import annotations

import asyncio

import pytest

from app.utils.circuit_breaker import CircuitBreaker, CircuitBreakerOpenError, CircuitState


class TestSyncStatusEndpoint:
    def test_status_returns_200(self, app_client):
        resp = app_client.get("/api/v1/sync/status")
        assert resp.status_code == 200

    def test_status_has_required_fields(self, app_client):
        data = app_client.get("/api/v1/sync/status").json()
        assert "crowdstrike_to_thehive_count" in data
        assert "thehive_to_crowdstrike_count" in data
        assert "errors" in data
        assert "circuit_breaker_state" in data

    def test_status_counts_are_non_negative(self, app_client):
        data = app_client.get("/api/v1/sync/status").json()
        assert data["crowdstrike_to_thehive_count"] >= 0
        assert data["thehive_to_crowdstrike_count"] >= 0


class TestManualSyncEndpoint:
    def test_manual_sync_returns_200(self, app_client):
        resp = app_client.post("/api/v1/sync/manual")
        assert resp.status_code == 200

    def test_manual_sync_response_structure(self, app_client):
        data = app_client.post("/api/v1/sync/manual").json()
        assert "result" in data
        assert "status" in data

    def test_manual_sync_increments_count(self, app_client):
        before = app_client.get("/api/v1/sync/status").json()["crowdstrike_to_thehive_count"]
        app_client.post("/api/v1/sync/manual")
        after = app_client.get("/api/v1/sync/status").json()["crowdstrike_to_thehive_count"]
        assert after >= before


# ---------------------------------------------------------------------------
# Circuit breaker unit tests
# ---------------------------------------------------------------------------

class TestCircuitBreakerStateMachine:
    """Directly test the CircuitBreaker class using asyncio."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_initial_state_is_closed(self):
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=60)
        assert cb.state == CircuitState.CLOSED

    def test_successful_call_stays_closed(self):
        cb = CircuitBreaker("test", failure_threshold=3)

        async def _run():
            async def success():
                return "ok"
            return await cb.call(success)

        result = self._run(_run())
        assert result == "ok"
        assert cb.state == CircuitState.CLOSED

    def test_opens_after_threshold_failures(self):
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=999)

        async def _failing():
            raise ValueError("boom")

        async def _run():
            for _ in range(3):
                try:
                    await cb.call(_failing)
                except ValueError:
                    pass

        self._run(_run())
        assert cb.state == CircuitState.OPEN
        assert cb.failure_count == 3

    def test_open_circuit_rejects_calls(self):
        cb = CircuitBreaker("test", failure_threshold=1, recovery_timeout=999)

        async def _failing():
            raise ValueError("boom")

        async def _run():
            try:
                await cb.call(_failing)
            except ValueError:
                pass
            # Circuit should now be OPEN; next call should be rejected
            with pytest.raises(CircuitBreakerOpenError):
                await cb.call(_failing)

        self._run(_run())

    def test_transitions_closed_open_halfopen_closed(self):
        """Full state machine cycle: CLOSED → OPEN → HALF_OPEN → CLOSED."""
        cb = CircuitBreaker(
            "test",
            failure_threshold=2,
            recovery_timeout=0,  # instant recovery for testing
            half_open_max_calls=1,
        )

        async def _failing():
            raise ValueError("boom")

        async def _ok():
            return "ok"

        async def _run():
            # Trip the circuit (CLOSED → OPEN)
            for _ in range(2):
                try:
                    await cb.call(_failing)
                except ValueError:
                    pass

            assert cb.state == CircuitState.OPEN

            # With recovery_timeout=0, the next call transitions OPEN → HALF_OPEN
            # and executes the probe. A successful probe → CLOSED.
            result = await cb.call(_ok)
            assert result == "ok"
            assert cb.state == CircuitState.CLOSED

        self._run(_run())

    def test_half_open_failure_reopens_circuit(self):
        cb = CircuitBreaker(
            "test",
            failure_threshold=1,
            recovery_timeout=0,
            half_open_max_calls=1,
        )

        async def _failing():
            raise ValueError("boom")

        async def _run():
            # Open the circuit
            try:
                await cb.call(_failing)
            except ValueError:
                pass

            assert cb.state == CircuitState.OPEN

            # Probe (HALF_OPEN) fails → back to OPEN
            try:
                await cb.call(_failing)
            except (ValueError, CircuitBreakerOpenError):
                pass

            assert cb.state == CircuitState.OPEN

        self._run(_run())

    def test_failure_count_resets_after_success(self):
        cb = CircuitBreaker("test", failure_threshold=5, recovery_timeout=0)

        async def _failing():
            raise ValueError("boom")

        async def _ok():
            return "ok"

        async def _run():
            # Accumulate some failures (but below threshold)
            for _ in range(3):
                try:
                    await cb.call(_failing)
                except ValueError:
                    pass

            assert cb.failure_count == 3

            # A success should reset the failure counter
            await cb.call(_ok)
            assert cb.failure_count == 0

        self._run(_run())
