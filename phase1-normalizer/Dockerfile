# ── Stage 1: Builder ──────────────────────────────────────────────────────────
# Install dependencies in an isolated layer so they don't bloat the final image.
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build tools needed for native extensions (e.g. jq bindings)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# Minimal image — only runtime dependencies and application code.
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="Security Alert Normalizer" \
      org.opencontainers.image.description="Phase 1 — Enriches and normalizes threat intel from VirusTotal and AbuseIPDB" \
      org.opencontainers.image.source="https://github.com/oznekcyber/security-automation" \
      org.opencontainers.image.licenses="MIT"

# Create a non-root user for runtime security
RUN groupadd --gid 1001 appgroup \
    && useradd --uid 1001 --gid appgroup --no-create-home --shell /sbin/nologin appuser

RUN mkdir -p /app && chown appuser:appgroup /app

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy application source — owned by the non-root user
COPY --chown=appuser:appgroup src/ ./src/
COPY --chown=appuser:appgroup main.py .

# Switch to non-root user
USER appuser

# Default: run the demo (no API keys required) — override with your own args
ENTRYPOINT ["python", "main.py"]
CMD ["--demo"]
