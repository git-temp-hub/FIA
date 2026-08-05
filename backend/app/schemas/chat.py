"""
Chat API Schemas
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ChatQueryRequest(BaseModel):
    """A question about a specific investigation."""

    investigation_id: str

    question: str = Field(..., min_length=1)

    top_k: int = Field(6, ge=1, le=20)


class EvidenceReference(BaseModel):
    """A retrieved evidence record referenced by the answer."""

    index: int

    evidence_id: int | None = None

    plugin_name: str | None = None

    artifact_type: str | None = None

    confidence_score: int | None = None

    document: str

    score: float | None = None


class ChatQueryResponse(BaseModel):
    """Evidence-backed AI answer."""

    investigation_id: str

    question: str

    answer: str

    confidence: int

    insufficient: bool

    citations: list[EvidenceReference]

    references: list[EvidenceReference]


class ChatHistoryMessage(BaseModel):
    """A single stored conversation message."""

    id: int

    role: str

    content: str

    citations: list[EvidenceReference] | None = None

    confidence: int | None = None

    created_at: datetime


class ChatHistoryResponse(BaseModel):
    """Full conversation history for an investigation."""

    investigation_id: str

    messages: list[ChatHistoryMessage]


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "ChatQueryRequest",
    "EvidenceReference",
    "ChatQueryResponse",
    "ChatHistoryMessage",
    "ChatHistoryResponse",
]
