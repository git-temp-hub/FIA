"""
Evidence API Schemas
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


def severity_for(confidence_score: int | None) -> str:
    """
    Derive a severity label from a confidence score.

    The PluginResult model stores a numeric confidence score rather
    than an explicit severity column, so the label is derived here.
    """

    if confidence_score is None:
        return "unknown"

    if confidence_score >= 90:
        return "high"

    if confidence_score >= 70:
        return "medium"

    return "low"


class EvidenceItem(BaseModel):
    """A single evidence record as displayed in the explorer."""

    id: int

    plugin: str

    artifact_type: str

    artifact_name: str

    artifact_value: str

    confidence_score: int

    severity: str

    classification_state: str = "unknown"

    risk_reasons: list[str] = Field(default_factory=list)

    risk_indicators: list[str] = Field(default_factory=list)

    created_at: datetime


class EvidenceListResponse(BaseModel):
    """Paginated evidence listing with available filter options."""

    items: list[EvidenceItem]

    total: int

    page: int

    page_size: int

    total_pages: int

    plugins: list[str]

    artifact_types: list[str]


class EvidenceDetailResponse(BaseModel):
    """Full details for a single evidence record."""

    id: int

    plugin_execution_id: int

    plugin: str

    artifact_type: str

    artifact_name: str

    artifact_value: str

    confidence_score: int

    severity: str

    classification_state: str = "unknown"

    risk_reasons: list[str] = Field(default_factory=list)

    risk_indicators: list[str] = Field(default_factory=list)

    created_at: datetime

    memory_dump_id: int | None = None

    investigation_id: str | None = None


class EvidenceInvestigationSummary(BaseModel):
    """Aggregated summary of an investigation for the evidence explorer."""

    investigation_id: str

    filename: str

    status: str

    progress: int

    evidence_count: int

    plugin_count: int


class EvidenceInvestigationListResponse(BaseModel):
    """List of investigation summaries."""

    items: list[EvidenceInvestigationSummary]


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "severity_for",
    "EvidenceItem",
    "EvidenceListResponse",
    "EvidenceDetailResponse",
    "EvidenceInvestigationSummary",
    "EvidenceInvestigationListResponse",
]
