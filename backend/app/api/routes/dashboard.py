"""
Dashboard API

Live statistics for the FIA dashboard, sourced from SQLite.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from pathlib import Path

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.database.database import database_manager, get_db
from app.database.repositories import (
    ChatMessageRepository,
    MemoryDumpRepository,
    PluginExecutionRepository,
    PluginResultRepository,
    ReportRepository,
)
from app.schemas.dashboard import (
    DashboardEvidenceDistribution,
    DashboardRecentInvestigation,
    DashboardStatsResponse,
    DashboardTrendPoint,
    SystemHealth,
)

logger = get_logger(__name__)

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
)

# ==============================================================================
# Response Caching
# ==============================================================================

_CACHE_TTL_SECONDS: float = 5.0

_cached_payload: dict | None = None
_cached_at: float = 0.0


# ==============================================================================
# Health Helpers
# ==============================================================================


def _database_status() -> str:
    """
    Return "connected" or "disconnected" based on a real DB ping.
    """

    try:
        database_manager.verify_connection()
        return "connected"
    except Exception as exc:
        logger.warning("Dashboard database health check failed: %s", exc)
        return "disconnected"


def _ollama_status() -> str:
    """
    Best-effort Ollama connectivity check with a short timeout.
    """

    try:
        with httpx.Client(timeout=1.0) as client:
            response = client.get(
                f"{settings.ollama.base_url.rstrip('/')}/api/tags"
            )
            if response.status_code == 200:
                return "connected"
    except Exception as exc:
        logger.debug("Ollama health check failed: %s", exc)

    return "unavailable"


def _chromadb_status() -> str:
    """
    Return "ready" when the vector store directory exists.
    """

    try:
        path = Path(settings.vector_database.path)
        if path.exists():
            return "ready"
    except Exception as exc:
        logger.debug("ChromaDB health check failed: %s", exc)

    return "unavailable"


# ==============================================================================
# Statistics Builder
# ==============================================================================


def _build_success_rate(
    execution_stats: dict[str, int],
) -> tuple[int, float]:
    """
    Compute plugin execution success rate from status counts.
    """

    completed = execution_stats.get("completed", 0)
    failed = execution_stats.get("failed", 0)
    terminal = completed + failed

    rate = round(completed / terminal * 100, 1) if terminal else 0.0

    return completed + failed, rate


def _build_trend(
    counts_by_day: list[tuple],
) -> list[DashboardTrendPoint]:
    """
    Build a complete day-by-day trend series, filling missing days.
    """

    by_date = {str(day): count for day, count in counts_by_day}

    today = datetime.utcnow()
    points: list[DashboardTrendPoint] = []

    for offset in range(6, -1, -1):
        day = today - timedelta(days=offset)
        key = day.strftime("%Y-%m-%d")
        points.append(
            DashboardTrendPoint(
                day=key,
                label=day.strftime("%a %d %b"),
                investigations=by_date.get(key, 0),
            )
        )

    return points


def _build_stats(
    db: Session,
) -> dict:
    """
    Gather all dashboard statistics from the database.
    """

    memory_dump_repository = MemoryDumpRepository(db)
    plugin_result_repository = PluginResultRepository(db)
    plugin_execution_repository = PluginExecutionRepository(db)
    chat_message_repository = ChatMessageRepository(db)
    report_repository = ReportRepository(db)

    total_investigations = memory_dump_repository.count()

    execution_stats = plugin_execution_repository.execution_stats()
    plugin_executions_total, success_rate = _build_success_rate(
        execution_stats
    )

    recent_rows = memory_dump_repository.list_recent_with_evidence(
        limit=5
    )

    recent_investigations = [
        DashboardRecentInvestigation(
            investigation_id=row.investigation_id or "",
            filename=row.filename,
            status=row.status,
            progress=row.progress,
            uploaded_at=row.uploaded_at,
            evidence_count=row.evidence_count,
        )
        for row in recent_rows
    ]

    trend = _build_trend(
        memory_dump_repository.count_by_day(days=7)
    )

    distribution = [
        DashboardEvidenceDistribution(
            artifact_type=artifact_type,
            count=count,
        )
        for artifact_type, count in
        plugin_result_repository.get_artifact_type_distribution(limit=8)
    ]

    health = SystemHealth(
        application=settings.application.name,
        version=settings.application.version,
        environment=settings.application.environment,
        database=_database_status(),
        ollama=_ollama_status(),
        chromadb=_chromadb_status(),
    )

    return DashboardStatsResponse(
        total_investigations=total_investigations,
        total_memory_dumps=total_investigations,
        total_evidence=plugin_result_repository.count(),
        total_reports=report_repository.count(),
        total_ai_queries=chat_message_repository.count_by_role("user"),
        plugin_executions_total=plugin_executions_total,
        plugin_execution_success_rate=success_rate,
        recent_investigations=recent_investigations,
        investigation_trend=trend,
        evidence_distribution=distribution,
        system_health=health,
    ).model_dump()


# ==============================================================================
# Endpoints
# ==============================================================================


@router.get(
    "/stats",
    response_model=DashboardStatsResponse,
)
async def dashboard_stats(
    db: Session = Depends(get_db),
):
    """
    Return live dashboard statistics.
    """

    global _cached_payload, _cached_at

    now = time.monotonic()

    if (
        _cached_payload is not None
        and now - _cached_at < _CACHE_TTL_SECONDS
    ):
        return _cached_payload

    try:
        payload = _build_stats(db)
    except Exception as exc:
        logger.exception("Failed to build dashboard statistics.")
        raise HTTPException(
            status_code=500,
            detail="Unable to load dashboard statistics.",
        ) from exc

    _cached_payload = payload
    _cached_at = now

    return payload


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "router",
]
