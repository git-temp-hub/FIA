"""
Report API Schemas
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class ReportInfo(BaseModel):
    """Metadata for a generated report."""

    id: int

    investigation_id: str

    case_name: str

    dump_filename: str | None = None

    sha256_hash: str | None = None

    filename: str

    file_size: int

    status: str

    error_message: str | None = None

    generated_at: datetime


class ReportListResponse(BaseModel):
    """List of generated reports."""

    items: list[ReportInfo]


class ReportGenerateResponse(ReportInfo):
    """Result of a report generation request."""

    message: str


class ReportDetailResponse(ReportInfo):
    """Full report details plus investigation statistics."""

    memory_dump_filename: str | None = None

    investigation_status: str | None = None

    total_plugins: int = 0

    successful_plugins: int = 0

    failed_plugins: int = 0

    total_evidence: int = 0

    investigation_duration: float = 0.0


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "ReportInfo",
    "ReportListResponse",
    "ReportGenerateResponse",
    "ReportDetailResponse",
]
