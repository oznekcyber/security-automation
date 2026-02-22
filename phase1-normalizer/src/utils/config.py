"""
Configuration management for Security Alert Normalizer.

Loads settings from environment variables or a .env file.
All API keys are treated as secrets and never logged.
"""

import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

# Load .env from repo root if present — no-op if the file doesn't exist
load_dotenv()


@dataclass(frozen=True)
class Config:
    """Immutable runtime configuration."""

    virustotal_api_key: str
    abuseipdb_api_key: str
    webhook_url: str = ""

    # HTTP client settings
    request_timeout: int = 30
    max_retries: int = 3
    retry_backoff_factor: float = 1.5

    # Output settings
    output_file: str = "normalized_alerts.json"

    # Indicators to enrich — populated from CLI, not from env
    ip_addresses: list = field(default_factory=list)
    file_hashes: list = field(default_factory=list)


def load_config(**overrides) -> Config:
    """
    Build a Config instance from environment variables.

    Any keyword argument passed in will override the corresponding
    env var (used by the CLI to inject CLI-supplied values).

    Raises:
        ValueError: If required API keys are missing.
    """
    vt_key = overrides.get("virustotal_api_key") or os.getenv("VIRUSTOTAL_API_KEY", "")
    abuse_key = overrides.get("abuseipdb_api_key") or os.getenv("ABUSEIPDB_API_KEY", "")

    if not vt_key:
        raise ValueError(
            "VIRUSTOTAL_API_KEY is not set. "
            "Add it to your .env file or export it as an environment variable."
        )
    if not abuse_key:
        raise ValueError(
            "ABUSEIPDB_API_KEY is not set. "
            "Add it to your .env file or export it as an environment variable."
        )

    return Config(
        virustotal_api_key=vt_key,
        abuseipdb_api_key=abuse_key,
        webhook_url=overrides.get("webhook_url") or os.getenv("WEBHOOK_URL", ""),
        request_timeout=int(
            overrides.get("request_timeout") or os.getenv("REQUEST_TIMEOUT", 30)
        ),
        max_retries=int(
            overrides.get("max_retries") or os.getenv("MAX_RETRIES", 3)
        ),
        retry_backoff_factor=float(
            overrides.get("retry_backoff_factor")
            or os.getenv("RETRY_BACKOFF_FACTOR", 1.5)
        ),
        output_file=overrides.get("output_file") or os.getenv(
            "OUTPUT_FILE", "normalized_alerts.json"
        ),
        ip_addresses=overrides.get("ip_addresses", []),
        file_hashes=overrides.get("file_hashes", []),
    )
