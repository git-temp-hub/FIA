"""
RAG API

Semantic evidence search and investigation indexing.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.database import get_db
from app.schemas.rag import (
    RAGIndexResponse,
    RAGSearchItem,
    RAGSearchResponse,
)
from app.services.rag.indexing_service import rag_indexing_service
from app.services.rag.rag_pipeline import rag_pipeline

logger = get_logger(__name__)

router = APIRouter(
    prefix="/rag",
    tags=["RAG"],
)


@router.post(
    "/index/{investigation_id}",
    response_model=RAGIndexResponse,
)
async def index_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    """
    Index all evidence for an investigation into ChromaDB.
    """

    try:
        result = rag_indexing_service.index_investigation(
            investigation_id,
            db,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.exception(
            "RAG indexing failed for investigation '%s'.",
            investigation_id,
        )
        raise HTTPException(
            status_code=500,
            detail="Indexing failed. Please try again.",
        ) from exc

    return RAGIndexResponse(
        investigation_id=investigation_id,
        status="indexed",
        indexed=result["indexed"],
        total=result["total"],
        removed=result["removed"],
    )


@router.get(
    "/search",
    response_model=RAGSearchResponse,
)
async def rag_search(
    query: str,
    investigation_id: str | None = None,
    top_k: int = Query(5, ge=1, le=50),
):
    """
    Perform semantic similarity search over indexed evidence.
    """

    try:
        ranked = rag_pipeline.search_evidence(
            question=query,
            top_k=top_k,
            investigation_id=investigation_id,
        )
    except Exception as exc:
        logger.exception(
            "Semantic search failed for query '%s'.",
            query,
        )
        raise HTTPException(
            status_code=500,
            detail=(
                "Semantic search failed. "
                "Ensure the investigation has been indexed."
            ),
        ) from exc

    items: list[RAGSearchItem] = []

    for match in ranked:

        metadata = match.get("metadata") or {}

        items.append(
            RAGSearchItem(
                evidence_id=metadata.get("evidence_id"),
                investigation_id=metadata.get("investigation_id"),
                plugin_name=metadata.get("plugin_name"),
                artifact_type=metadata.get("artifact_type"),
                confidence_score=metadata.get("confidence_score"),
                document=match.get("document", ""),
                distance=match.get("distance"),
                score=match.get("score"),
            )
        )

    return RAGSearchResponse(
        query=query,
        items=items,
        count=len(items),
    )
