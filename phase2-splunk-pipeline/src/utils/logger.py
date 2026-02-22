"""Logging helpers for the Splunk ingestion pipeline.

Two separate log streams are managed here:

* **application logger** – console output at INFO+ for general pipeline
  activity (event generation, batch stats, errors).
* **shipper logger** – optionally also writes to a dedicated file so that
  every HEC HTTP request/response can be audited independently of the main
  application log.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

# Names used across the codebase to obtain the two loggers.
APP_LOGGER_NAME = "phase2.app"
SHIPPER_LOGGER_NAME = "phase2.shipper"

_configured = False


def configure_logging(level: str = "INFO", log_file: Optional[str] = None) -> None:
    """Set up the root handler hierarchy.

    Safe to call multiple times – subsequent calls are no-ops.

    Parameters
    ----------
    level:
        Minimum log level for the console handler (e.g. ``"DEBUG"``,
        ``"INFO"``, ``"WARNING"``).
    log_file:
        When provided, shipper activity is *also* written to this path in
        addition to the console.
    """
    global _configured
    if _configured:
        return
    _configured = True

    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # ── console handler ───────────────────────────────────────────────────────
    console_fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s – %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(console_fmt)

    # ── application logger ────────────────────────────────────────────────────
    app_logger = logging.getLogger(APP_LOGGER_NAME)
    app_logger.setLevel(numeric_level)
    app_logger.addHandler(console_handler)
    app_logger.propagate = False

    # ── shipper logger ────────────────────────────────────────────────────────
    shipper_logger = logging.getLogger(SHIPPER_LOGGER_NAME)
    shipper_logger.setLevel(logging.DEBUG)  # capture everything to file
    shipper_logger.addHandler(console_handler)
    shipper_logger.propagate = False

    if log_file:
        file_fmt = logging.Formatter(
            fmt="%(asctime)s [%(levelname)-8s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        try:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(file_fmt)
            shipper_logger.addHandler(file_handler)
        except OSError as exc:
            app_logger.warning("Could not open shipper log file %r: %s", log_file, exc)


def get_logger(name: str) -> logging.Logger:
    """Return a named child of the application logger.

    Parameters
    ----------
    name:
        Dotted module/component name appended to ``phase2.app``.

    Returns
    -------
    logging.Logger
    """
    return logging.getLogger(f"{APP_LOGGER_NAME}.{name}")
