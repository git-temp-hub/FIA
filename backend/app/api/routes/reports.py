"""
Reports API

Report generation, listing, detail, and PDF download.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.database import get_db
from app.database.repositories import (
    MemoryDumpRepository,
    ReportRepository,
)
from app.models.report import Report
from app.schemas.report import (
    ReportDetailResponse,
    ReportGenerateResponse,
    ReportInfo,
    ReportListResponse,
)
from app.services.report_service import report_service

logger = get_logger(__name__)

router = APIRouter(
    prefix="/reports",
    tags=["Reports"],
)


def _report_info(report: Report) -> ReportInfo:
    """
    Map a Report model into its API schema.
    """

    return ReportInfo(
        id=report.id,
        investigation_id=report.investigation_id,
        case_name=report.case_name,
        dump_filename=report.dump_filename,
        sha256_hash=report.sha256_hash,
        filename=report.filename,
        file_size=report.file_size,
        status=report.status,
        error_message=report.error_message,
        generated_at=report.generated_at,
    )


@router.post(
    "/generate/{investigation_id}",
    response_model=ReportGenerateResponse,
)
async def generate_report(
    investigation_id: str,
    session_id: str | None = None,
    db: Session = Depends(get_db),
):
    """
    Generate a complete investigation report and store its metadata.

    An optional ``session_id`` restricts the AI Investigation Summary
    to a single conversation session.
    """

    memory_dump_repository = MemoryDumpRepository(db)

    investigation = (
        memory_dump_repository.get_by_investigation_id(
            investigation_id
        )
    )

    if investigation is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found.",
        )

    try:
        generated = report_service.generate(
            investigation_id,
            db,
            session_id=session_id,
        )
    except Exception as exc:
        logger.exception(
            "Report generation failed for investigation '%s'.",
            investigation_id,
        )
        raise HTTPException(
            status_code=500,
            detail=f"Report generation failed: {exc}",
        ) from exc

    report_repository = ReportRepository(db)

    report = report_repository.create(
        Report(
            investigation_id=generated["investigation_id"],
            case_name=generated["case_name"],
            dump_filename=generated["dump_filename"],
            sha256_hash=generated["sha256_hash"],
            filename=generated["filename"],
            file_path=generated["file_path"],
            file_size=generated["file_size"],
            status="generated",
            generated_at=generated["generated_at"],
        )
    )

    logger.info(
        "Report %d persisted for investigation '%s'.",
        report.id,
        investigation_id,
    )

    return ReportGenerateResponse(
        **_report_info(report).model_dump(),
        message="Report generated successfully.",
    )


@router.get(
    "",
    response_model=ReportListResponse,
)
async def list_reports(
    db: Session = Depends(get_db),
):
    """
    Return every generated report, newest first.
    """

    report_repository = ReportRepository(db)

    reports = report_repository.get_all_ordered()

    return ReportListResponse(
        items=[_report_info(report) for report in reports]
    )


@router.get(
    "/download/{report_id}",
)
async def download_report(
    report_id: int,
    db: Session = Depends(get_db),
):
    """
    Download the PDF file for a report.
    """

    report_repository = ReportRepository(db)

    report = report_repository.get_by_id(report_id)

    if report is None:
        raise HTTPException(
            status_code=404,
            detail="Report not found.",
        )

    report_path = Path(report.file_path)

    if not report_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Report file is missing.",
        )

    return FileResponse(
        path=str(report_path),
        media_type="application/pdf",
        filename=report.filename,
    )


@router.get(
    "/{report_id}",
    response_model=ReportDetailResponse,
)
async def report_detail(
    report_id: int,
    db: Session = Depends(get_db),
):
    """
    Return report metadata plus investigation statistics.
    """

    report_repository = ReportRepository(db)

    report = report_repository.get_by_id(report_id)

    if report is None:
        raise HTTPException(
            status_code=404,
            detail="Report not found.",
        )

    statistics = {
        "investigation_status": None,
        "total_plugins": 0,
        "successful_plugins": 0,
        "failed_plugins": 0,
        "total_evidence": 0,
        "investigation_duration": 0.0,
        "memory_dump_filename": report.dump_filename,
    }

    try:
        data = report_service.gather_investigation_data(
            report.investigation_id,
            db,
        )
        statistics.update({
            "investigation_status": data["investigation_status"],
            "total_plugins": data["total_plugins"],
            "successful_plugins": data["successful_plugins"],
            "failed_plugins": data["failed_plugins"],
            "total_evidence": data["total_evidence"],
            "investigation_duration": data["investigation_duration"],
            "memory_dump_filename": data["dump_filename"],
        })
    except ValueError:
        logger.warning(
            "Investigation '%s' no longer available for report %d.",
            report.investigation_id,
            report.id,
        )

    info = _report_info(report)

    return ReportDetailResponse(
        **info.model_dump(),
        memory_dump_filename=statistics["memory_dump_filename"],
        investigation_status=statistics["investigation_status"],
        total_plugins=statistics["total_plugins"],
        successful_plugins=statistics["successful_plugins"],
        failed_plugins=statistics["failed_plugins"],
        total_evidence=statistics["total_evidence"],
        investigation_duration=statistics["investigation_duration"],
    )
