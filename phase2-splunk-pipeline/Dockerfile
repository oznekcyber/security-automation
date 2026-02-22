# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements.txt* ./
RUN pip install --no-cache-dir --upgrade pip \
    && if [ -f requirements.txt ]; then \
         pip install --no-cache-dir --prefix=/install -r requirements.txt; \
       fi


# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="Splunk Log Ingestion Pipeline" \
      org.opencontainers.image.description="Phase 2 — Splunk HEC log ingestion and normalization pipeline" \
      org.opencontainers.image.source="https://github.com/oznekcyber/security-automation"

RUN groupadd --gid 1001 appgroup \
    && useradd --uid 1001 --gid appgroup --no-create-home --shell /sbin/nologin appuser

WORKDIR /app

COPY --from=builder /install /usr/local

COPY --chown=appuser:appgroup . .

USER appuser

ENTRYPOINT ["python"]
CMD ["main.py"]
