"""
RAG API Schemas
"""

from __future__ import annotations

from pydantic import BaseModel


class RAGIndexResponse(BaseModel):
    """Result of indexing an investigation's evidence."""

    investigation_id: str

    status: str

    indexed: int

    total: int

    removed: int


class RAGSearchItem(BaseModel):
    """A single ranked semantic search result."""

    evidence_id: int | None = None

    investigation_id: str | None = None

    plugin_name: str | None = None

    artifact_type: str | None = None

    confidence_score: int | None = None

    document: str

    distance: float | None = None

    score: float | None = None


class RAGSearchResponse(BaseModel):
    """Ranked semantic search results."""

    query: str

    items: list[RAGSearchItem]

    count: int


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "RAGIndexResponse",
    "RAGSearchItem",
    "RAGSearchResponse",
]
