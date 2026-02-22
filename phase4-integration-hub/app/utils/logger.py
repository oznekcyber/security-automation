"""Structured JSON logging configuration for the Integration Hub."""

import logging
import sys
from typing import Any

try:
    import structlog

    _structlog_available = True
except ImportError:
    _structlog_available = False


def configure_logging(log_level: str = "INFO") -> None:
    """Configure structured JSON logging for the application.

    Uses structlog with the stdlib logging backend when available (so that
    ``add_logger_name`` can correctly read ``logger.name``).  Falls back to
    plain stdlib JSON-formatted logging otherwise.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    if _structlog_available:
        # Route structlog through stdlib so add_logger_name works correctly
        logging.basicConfig(
            level=level,
            stream=sys.stdout,
            format="%(message)s",  # structlog renders the full JSON line
        )
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.stdlib.add_log_level,
                structlog.stdlib.add_logger_name,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(level),
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )
    else:
        logging.basicConfig(
            level=level,
            format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
                   '"logger": "%(name)s", "message": "%(message)s"}',
            stream=sys.stdout,
        )


def get_logger(name: str) -> Any:
    """Return a logger instance.

    Returns a structlog logger when available, otherwise a standard library logger.
    Both support keyword-argument extra fields in log calls.
    """
    if _structlog_available:
        return structlog.get_logger(name)
    return logging.getLogger(name)
