"""
Main FastAPI Application for the AI Memory Forensic Investigation Assistant.

This module is the application's entry point. It creates and configures
the FastAPI application and coordinates the startup and shutdown of
all infrastructure components.

Author:
    FIA Development Team
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import settings
from app.core.logging import get_logger
from app.database.database import database_manager

logger = get_logger(__name__)

# ==============================================================================
# Application Lifespan
# ==============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage the application lifecycle.

    This function is executed automatically by FastAPI.

    Startup:
        - Verify configuration
        - Initialize infrastructure
        - Verify database

    Shutdown:
        - Perform cleanup operations
    """

    logger.info("=" * 70)
    logger.info("Starting AI Memory Forensic Investigation Assistant")
    logger.info("=" * 70)

    logger.info(
        "Application: %s",
        settings.application.name,
    )

    logger.info(
        "Version: %s",
        settings.application.version,
    )

    logger.info(
        "Environment: %s",
        settings.application.environment,
    )

    logger.info("Initializing infrastructure...")

    database_manager.initialize()

    logger.info("Application startup completed successfully.")

    try:
        yield

    finally:

        logger.info("Shutting down FIA backend...")

        logger.info("Application shutdown completed.")

# ==============================================================================
# FastAPI Application
# ==============================================================================

app = FastAPI(
    title=settings.application.name,
    version=settings.application.version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


# ==============================================================================
# Root Endpoint
# ==============================================================================


@app.get(
    "/",
    tags=["System"],
    summary="Application Information",
)
async def root() -> dict[str, str]:
    """
    Return basic application information.
    """

    return {
        "application": settings.application.name,
        "version": settings.application.version,
        "environment": settings.application.environment,
        "status": "running",
    }


# ==============================================================================
# Health Check Endpoint
# ==============================================================================


@app.get(
    "/health",
    tags=["System"],
    summary="Health Check",
)
async def health_check() -> dict[str, str]:
    """
    Basic health check endpoint.
    """

    logger.info("Health check requested.")

    return {
        "status": "healthy",
        "database": "connected",
        "application": settings.application.name,
    }

from app.api.routes.upload import router as upload_router

app.include_router(upload_router)

# Future API routers will be registered here.
#
# Example:
#
# from app.api.routes.upload import router as upload_router
# from app.api.routes.investigation import router as investigation_router
#
# app.include_router(upload_router, prefix="/api/v1")
# app.include_router(investigation_router, prefix="/api/v1")


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "app",
]