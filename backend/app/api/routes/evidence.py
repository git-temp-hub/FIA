"""
Evidence API

Browse normalized forensic evidence produced by the investigation pipeline.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.database import get_db
from app.database.repositories import (
    MemoryDumpRepository,
    PluginExecutionRepository,
    PluginResultRepository,
)
from app.models.plugin_result import PluginResult
from app.schemas.evidence import (
    EvidenceDetailResponse,
    EvidenceInvestigationListResponse,
    EvidenceInvestigationSummary,
    EvidenceItem,
    EvidenceListResponse,
    severity_for,
)

logger = get_logger(__name__)

router = APIRouter(
    prefix="/evidence",
    tags=["Evidence"],
)


def _serialize_item(
    result: PluginResult,
) -> EvidenceItem:
    """
    Build an EvidenceItem from a PluginResult row.
    """

    return EvidenceItem(
        id=result.id,
        plugin=result.plugin_execution.plugin_name,
        artifact_type=result.artifact_type,
        artifact_name=result.artifact_name,
        artifact_value=result.artifact_value,
        confidence_score=result.confidence_score,
        severity=severity_for(result.confidence_score),
        created_at=result.created_at,
    )


@router.get(
    "/investigations",
    response_model=EvidenceInvestigationListResponse,
)
async def list_evidence_investigations(
    db: Session = Depends(get_db),
):
    """
    List aggregated investigation summaries for the evidence explorer.
    """

    repository = PluginResultRepository(db)

    try:
        summaries = [
            EvidenceInvestigationSummary(
                investigation_id=row.investigation_id,
                filename=row.filename,
                status=row.status,
                progress=row.progress,
                evidence_count=row.evidence_count,
                plugin_count=row.plugin_count,
            )
            for row in repository.list_investigations()
        ]
    except Exception as exc:
        logger.exception(
            "Failed to list evidence investigations."
        )
        raise HTTPException(
            status_code=500,
            detail="Unable to load investigations.",
        ) from exc

    return EvidenceInvestigationListResponse(
        items=summaries,
    )


@router.get(
    "/",
    response_model=EvidenceListResponse,
)
async def list_evidence(
    investigation_id: str | None = None,
    plugin: str | None = None,
    artifact_type: str | None = None,
    severity: Literal["high", "medium", "low"] | None = None,
    search: str | None = None,
    sort_by: Literal["id", "artifact_type", "artifact_name", "created_at"] = "id",
    sort_order: Literal["asc", "desc"] = "desc",
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """
    List evidence with filtering, sorting, and pagination.
    """

    repository = PluginResultRepository(db)

    try:
        results, total = repository.search(
            investigation_id=investigation_id,
            plugin=plugin,
            artifact_type=artifact_type,
            severity=severity,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
            page=page,
            page_size=page_size,
        )

        total_pages = (total + page_size - 1) // page_size if total else 0

        return EvidenceListResponse(
            items=[_serialize_item(result) for result in results],
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            plugins=repository.get_plugin_names(
                investigation_id=investigation_id,
            ),
            artifact_types=repository.get_artifact_types(
                investigation_id=investigation_id,
            ),
        )
    except Exception as exc:
        logger.exception(
            "Failed to list evidence."
        )
        raise HTTPException(
            status_code=500,
            detail="Unable to load evidence.",
        ) from exc


@router.get(
    "/{evidence_id}",
    response_model=EvidenceDetailResponse,
)
async def evidence_detail(
    evidence_id: int,
    db: Session = Depends(get_db),
):
    """
    Return full details for a single evidence record.
    """

    plugin_result_repository = PluginResultRepository(db)
    plugin_execution_repository = PluginExecutionRepository(db)
    memory_dump_repository = MemoryDumpRepository(db)

    result = plugin_result_repository.get_by_id(evidence_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Evidence not found.",
        )

    execution = plugin_execution_repository.get_by_id(
        result.plugin_execution_id
    )

    memory_dump_id: int | None = None
    investigation_id: str | None = None

    if execution is not None:
        memory_dump_id = execution.memory_dump_id

        memory_dump = memory_dump_repository.get_by_id(
            execution.memory_dump_id
        )

        if memory_dump is not None:
            investigation_id = memory_dump.investigation_id

    return EvidenceDetailResponse(
        id=result.id,
        plugin_execution_id=result.plugin_execution_id,
        plugin=(
            execution.plugin_name
            if execution is not None
            else result.artifact_name
        ),
        artifact_type=result.artifact_type,
        artifact_name=result.artifact_name,
        artifact_value=result.artifact_value,
        confidence_score=result.confidence_score,
        severity=severity_for(result.confidence_score),
        created_at=result.created_at,
        memory_dump_id=memory_dump_id,
        investigation_id=investigation_id,
    )
