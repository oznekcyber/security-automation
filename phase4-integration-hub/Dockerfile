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

LABEL org.opencontainers.image.title="API Integration Hub" \
      org.opencontainers.image.description="Phase 4 — FastAPI integration hub for security automation APIs" \
      org.opencontainers.image.source="https://github.com/oznekcyber/security-automation"

RUN groupadd --gid 1001 appgroup \
    && useradd --uid 1001 --gid appgroup --no-create-home --shell /sbin/nologin appuser

WORKDIR /app

COPY --from=builder /install /usr/local

COPY --chown=appuser:appgroup . .

USER appuser

EXPOSE 8000

ENTRYPOINT ["uvicorn"]
CMD ["main:app", "--host", "0.0.0.0", "--port", "8000"]
