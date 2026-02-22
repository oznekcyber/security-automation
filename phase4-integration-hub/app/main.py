"""FastAPI application entry point for the Security Integration Hub."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import health, sync, webhooks
from app.services.sync_manager import SyncManager
from app.utils.logger import configure_logging, get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown."""
    configure_logging(log_level=os.getenv("LOG_LEVEL", "INFO"))
    logger.info("integration_hub_starting")

    app.state.sync_manager = SyncManager()
    logger.info("sync_manager_initialized")

    yield

    logger.info("integration_hub_shutting_down")
    await app.state.sync_manager.close()


app = FastAPI(
    title="Security Integration Hub",
    version="1.0.0",
    description="Bidirectional API middleware between CrowdStrike Falcon and TheHive.",
    docs_url="/docs",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "http://localhost:3000",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(webhooks.router, prefix="/api/v1/webhooks", tags=["Webhooks"])
app.include_router(sync.router, prefix="/api/v1/sync", tags=["Sync"])
app.include_router(health.router, prefix="/api/v1", tags=["Health"])
