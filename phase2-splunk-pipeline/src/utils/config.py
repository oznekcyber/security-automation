"""Configuration loader for the Splunk ingestion pipeline.

Reads settings from environment variables (via a .env file) and exposes a
typed :class:`Config` dataclass.  Call :func:`load_config` once at start-up
and pass the resulting object to every component that needs it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from dotenv import load_dotenv


@dataclass
class Config:
    """Typed configuration for every component in the pipeline."""

    # Splunk HEC settings
    splunk_url: str = "http://localhost:8088"
    hec_token: str = ""
    index_name: str = "security_events"
    normalizer_index: str = "threat_intel"

    # Batching / retry settings
    batch_size: int = 100
    max_retries: int = 3
    retry_backoff_factor: float = 1.5

    # Logging
    log_level: str = "INFO"
    shipper_log_file: str = "shipper.log"


def load_config(env_file: Optional[str] = None) -> Config:
    """Load configuration from environment variables.

    Parameters
    ----------
    env_file:
        Path to a ``.env`` file.  When *None* the default search path used by
        :func:`dotenv.load_dotenv` applies (i.e. looks for ``.env`` in the
        current directory and parents).

    Returns
    -------
    Config
        Fully populated configuration dataclass.
    """
    if env_file:
        load_dotenv(env_file, override=False)
    else:
        load_dotenv(override=False)

    def _int(key: str, default: int) -> int:
        try:
            return int(os.environ.get(key, default))
        except (ValueError, TypeError):
            return default

    def _float(key: str, default: float) -> float:
        try:
            return float(os.environ.get(key, default))
        except (ValueError, TypeError):
            return default

    return Config(
        splunk_url=os.environ.get("SPLUNK_URL", "http://localhost:8088").rstrip("/"),
        hec_token=os.environ.get("HEC_TOKEN", ""),
        index_name=os.environ.get("INDEX_NAME", "security_events"),
        normalizer_index=os.environ.get("NORMALIZER_INDEX", "threat_intel"),
        batch_size=_int("BATCH_SIZE", 100),
        max_retries=_int("MAX_RETRIES", 3),
        retry_backoff_factor=_float("RETRY_BACKOFF_FACTOR", 1.5),
        log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        shipper_log_file=os.environ.get("SHIPPER_LOG_FILE", "shipper.log"),
    )
