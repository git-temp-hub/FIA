"""
RAG Indexing Service for the AI Memory Forensic Investigation Assistant.

Chunks normalized evidence, generates embeddings, and stores the
vectors in ChromaDB using the existing EmbeddingManager and VectorStore.

Author:
    FIA Development Team
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.repositories import (
    MemoryDumpRepository,
    PluginResultRepository,
)
from app.services.rag.embedding_manager import EmbeddingManager
from app.services.rag.vector_store import VectorStore

logger = get_logger(__name__)


class RAGIndexingService:
    """
    Indexes normalized forensic evidence into the vector database.
    """

    def __init__(
        self,
        embedding_manager: EmbeddingManager | None = None,
        vector_store: VectorStore | None = None,
    ) -> None:

        self._embedding_manager = (
            embedding_manager
            if embedding_manager is not None
            else EmbeddingManager()
        )

        self._vector_store = (
            vector_store
            if vector_store is not None
            else VectorStore()
        )

        logger.info(
            "RAG Indexing Service initialized."
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def embedding_manager(self) -> EmbeddingManager:
        return self._embedding_manager

    @property
    def vector_store(self) -> VectorStore:
        return self._vector_store

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

    def index_investigation(
        self,
        investigation_id: str,
        session: Session,
    ) -> dict[str, int]:
        """
        Index every evidence record for an investigation.

        Existing vectors for the investigation are removed first so the
        operation is idempotent and supports re-indexing when an
        investigation is rerun.

        Parameters
        ----------
        investigation_id : str

        session : Session

        Returns
        -------
        dict
            {"indexed": int, "total": int, "removed": int}

        Raises
        ------
        ValueError
            If the investigation does not exist.
        """

        memory_dump_repository = MemoryDumpRepository(session)

        investigation = (
            memory_dump_repository.get_by_investigation_id(
                investigation_id
            )
        )

        if investigation is None:
            raise ValueError(
                f"Investigation not found: {investigation_id}"
            )

        plugin_result_repository = PluginResultRepository(session)

        results = plugin_result_repository.get_by_investigation(
            investigation_id
        )

        removed = self._vector_store.delete_by_metadata(
            {"investigation_id": investigation_id}
        )

        if not results:
            logger.info(
                "No evidence to index for investigation '%s'.",
                investigation_id,
            )
            return {
                "indexed": 0,
                "total": 0,
                "removed": removed,
            }

        ids: list[str] = []
        documents: list[str] = []
        metadatas: list[dict] = []

        for result in results:

            evidence_id = result.id

            plugin_name = (
                result.plugin_execution.plugin_name
                if result.plugin_execution is not None
                else result.artifact_name
            )

            document = self._embedding_manager.build_document({
                "artifact_name": result.artifact_name,
                "artifact_type": result.artifact_type,
                "artifact_value": result.artifact_value,
            })

            ids.append(f"ev-{evidence_id}")
            documents.append(document)
            metadatas.append({
                "investigation_id": investigation_id,
                "plugin_name": plugin_name,
                "artifact_type": result.artifact_type,
                "evidence_id": evidence_id,
                "confidence_score": result.confidence_score,
            })

        embeddings = self._embedding_manager.embed_documents(
            documents
        )

        self._vector_store.add_documents(
            ids=ids,
            documents=documents,
            embeddings=embeddings,
            metadatas=metadatas,
        )

        logger.info(
            "Indexed %d evidence records for investigation '%s'.",
            len(ids),
            investigation_id,
        )

        return {
            "indexed": len(ids),
            "total": len(results),
            "removed": removed,
        }


# ==============================================================================
# Singleton Instance
# ==============================================================================

rag_indexing_service = RAGIndexingService()


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "RAGIndexingService",
    "rag_indexing_service",
]
