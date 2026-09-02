"""
Main FastAPI Application for the AI Memory Forensic Investigation Assistant.

This module is the application's entry point. It creates and configures
the FastAPI application and coordinates the startup and shutdown of
all infrastructure components.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.chat import router as chat_router
from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.evidence import router as evidence_router
from app.api.routes.investigation import router as investigation_router
from app.api.routes.rag import router as rag_router
from app.api.routes.reports import router as reports_router
from app.api.routes.settings import router as settings_router
from app.api.routes.upload import router as upload_router

from app.core.config import settings
from app.core.logging import get_logger
from app.database.database import database_manager

logger = get_logger(__name__)

# ==============================================================================
# Application Lifespan
# ==============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):

    logger.info("=" * 70)
    logger.info("Starting AI Memory Forensic Investigation Assistant")
    logger.info("=" * 70)

    logger.info("Application: %s", settings.application.name)
    logger.info("Version: %s", settings.application.version)
    logger.info("Environment: %s", settings.application.environment)

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
# CORS Configuration
# ==============================================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        # Local development
        "http://localhost:5173",
        "http://127.0.0.1:5173",

        # LAN access (replace if your IP changes)
        "http://192.168.1.55:5173",
        "http://192.168.1.51:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================================================================
# API Routers
# ==============================================================================

app.include_router(upload_router)
app.include_router(investigation_router)
app.include_router(evidence_router)
app.include_router(rag_router)
app.include_router(chat_router)
app.include_router(reports_router)
app.include_router(dashboard_router)
app.include_router(settings_router)

# ==============================================================================
# Root Endpoint
# ==============================================================================


@app.get("/", tags=["System"], summary="Application Information")
async def root():

    return {
        "application": settings.application.name,
        "version": settings.application.version,
        "environment": settings.application.environment,
        "status": "running",
    }


# ==============================================================================
# Health Check
# ==============================================================================


@app.get("/health", tags=["System"], summary="Health Check")
async def health_check():

    logger.info("Health check requested.")

    database_status = "disconnected"

    try:
        database_manager.verify_connection()
        database_status = "connected"

    except Exception:

        logger.exception("Database connectivity failed.")
           
    return {
        "status": "healthy" if database_status == "connected" else "unhealthy",
        "database": database_status,
        "application": settings.application.name,
    }


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = ["app"]