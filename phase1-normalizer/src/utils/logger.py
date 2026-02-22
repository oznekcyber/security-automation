"""
Structured logging setup for Security Alert Normalizer.

Produces human-readable output to stdout and optionally to a log
file.  A single ``get_logger`` call is all any module needs.
"""

import logging
import sys
from typing import Optional


_LOG_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

# Track whether the root logger has already been configured so that
# multiple calls to get_logger() don't add duplicate handlers.
_configured = False


def configure_logging(level: str = "INFO", log_file: Optional[str] = None) -> None:
    """
    Configure the root logger once for the entire application.

    Args:
        level:    Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Optional path to a file where logs should also be written.
    """
    global _configured
    if _configured:
        return

    numeric_level = getattr(logging, level.upper(), logging.INFO)

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)

    handlers: list[logging.Handler] = [stream_handler]

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    logging.basicConfig(level=numeric_level, handlers=handlers, force=True)
    _configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger.

    Call ``configure_logging()`` before the first ``get_logger()``
    invocation if you need non-default settings; otherwise INFO-level
    stdout logging is used automatically.

    Args:
        name: Typically ``__name__`` of the calling module.

    Returns:
        A standard :class:`logging.Logger` instance.
    """
    if not _configured:
        configure_logging()
    return logging.getLogger(name)
