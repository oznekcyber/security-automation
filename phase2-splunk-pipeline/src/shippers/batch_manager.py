"""Batch manager for the Splunk HEC shipper.

Buffers events in-memory and flushes them to Splunk in configurable batch
sizes.  Supports use as a context manager so the buffer is always flushed on
exit, even if an exception is raised.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.shippers.hec_shipper import HECShipper
from src.utils.logger import get_logger

_log = get_logger("batch_manager")


class BatchManager:
    """Buffer events and flush them in batches to ``HECShipper``.

    Parameters
    ----------
    shipper:
        Initialised :class:`~src.shippers.hec_shipper.HECShipper` instance.
    batch_size:
        Maximum number of events to accumulate before an automatic flush.
    """

    def __init__(self, shipper: HECShipper, batch_size: int = 100) -> None:
        self._shipper = shipper
        self._batch_size = batch_size
        # Each buffered item is (event_dict, sourcetype, index_or_None)
        self._buffer: List[tuple[Dict[str, Any], str, Optional[str]]] = []

    # ── public API ────────────────────────────────────────────────────────────

    def add_event(
        self,
        event: Dict[str, Any],
        sourcetype: str,
        index: Optional[str] = None,
    ) -> None:
        """Append *event* to the internal buffer.

        Parameters
        ----------
        event:
            Raw event dict to buffer.
        sourcetype:
            Splunk sourcetype for this event.
        index:
            Splunk index override (optional).
        """
        self._buffer.append((event, sourcetype, index))
        self.flush_if_full()

    def flush(self) -> None:
        """Immediately send all buffered events to Splunk.

        Events that share the same ``(sourcetype, index)`` pair are grouped
        into a single HEC batch request to minimise round-trips.
        """
        if not self._buffer:
            return

        # Group by (sourcetype, index) for efficient batching.
        groups: Dict[tuple[str, Optional[str]], List[Dict[str, Any]]] = {}
        for ev, st, idx in self._buffer:
            key = (st, idx)
            groups.setdefault(key, []).append(ev)

        for (sourcetype, index), events in groups.items():
            _log.info(
                "Flushing %d events (sourcetype=%s, index=%s)",
                len(events),
                sourcetype,
                index,
            )
            self._shipper.send_batch(events, sourcetype=sourcetype, index=index)

        self._buffer.clear()

    def flush_if_full(self) -> None:
        """Flush only when the buffer has reached *batch_size* capacity."""
        if len(self._buffer) >= self._batch_size:
            self.flush()

    # ── context manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "BatchManager":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Flush remaining events on context exit, regardless of exceptions."""
        try:
            self.flush()
        except Exception as exc:  # noqa: BLE001
            _log.error("Error flushing buffer on context exit: %s", exc)
