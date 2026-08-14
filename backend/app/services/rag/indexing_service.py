"""
RAG Indexing Service for the AI Memory Forensic Investigation Assistant.

Streams normalized evidence in bounded pages, generates embeddings, and
stores the vectors in ChromaDB using the existing EmbeddingManager and
VectorStore.

Indexing is incremental and resumable:
* Evidence rows are streamed page by page (keyset pagination) so large
  investigations (~19k evidence rows) never load into memory at once.
* Already-indexed, unchanged evidence is skipped via the SQLite
  ``evidence_index_state`` table, so re-runs never re-embed needlessly.
* Each page commits its index-state checkpoint, so an interrupted run resumes
  from the last committed page.
* A per-service lock serializes indexing jobs, so two threads can never embed
  concurrently against the same loaded model.

SQLite (``plugin_results``) stays the authoritative evidence source; ChromaDB
remains only the semantic layer.

Author:
    FIA Development Team
"""

from __future__ import annotations

import hashlib
import threading
from typing import Final

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.database.repositories import (
    EvidenceIndexStateRepository,
    MemoryDumpRepository,
    PluginResultRepository,
)
from app.services.rag.embedding_manager import EmbeddingManager
from app.services.rag.vector_store import VectorStore

logger = get_logger(__name__)

# ChromaDB rejects a single batch larger than its maximum (5461).
# Target a conservative 1000 documents per embed/add so large
# investigations (~19k evidence rows) index reliably.
INDEXING_BATCH_SIZE: Final[int] = 1000

CHROMA_MAX_BATCH_SIZE: Final[int] = 5461


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

        self._batch_size = max(
            1,
            min(
                int(settings.rag.index_batch_size),
                CHROMA_MAX_BATCH_SIZE,
            ),
        )

        # Serializes indexing jobs so a single loaded model is never shared
        # between concurrent embed loops (lazy-index thread, /rag/index, ...).
        self._lock = threading.RLock()

        logger.info(
            "RAG Indexing Service initialized (batch_size=%d).",
            self._batch_size,
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

    @property
    def batch_size(self) -> int:
        """
        Return the number of evidence rows processed per index page.
        """

        return self._batch_size

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

        Indexing is incremental: rows whose persisted content hash already
        matches the vector store are skipped, and stale vectors for evidence
        rows that no longer exist are removed. The operation is resumable
        after failures because each page commits its index-state checkpoint.

        Parameters
        ----------
        investigation_id : str

        session : Session

        Returns
        -------
        dict
            {
                "indexed": newly embedded evidence rows,
                "total": evidence rows present in SQLite,
                "removed": stale vectors cleaned up,
            }

        Raises
        ------
        ValueError
            If the investigation does not exist.
        """

        with self._lock:
            return self._index_investigation_locked(
                investigation_id,
                session,
            )

    def _index_investigation_locked(
        self,
        investigation_id: str,
        session: Session,
    ) -> dict[str, int]:
        """Index an investigation under the service lock."""

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
        state_repository = EvidenceIndexStateRepository(session)

        total = plugin_result_repository.count_by_investigation(
            investigation_id
        )

        state_map = state_repository.get_by_investigation(
            investigation_id
        )

        if total == 0:
            logger.info(
                "No evidence to index for investigation '%s'.",
                investigation_id,
            )
            return {
                "indexed": 0,
                "total": 0,
                "removed": 0,
            }

        newly_indexed = 0
        seen_ids: set[int] = set()
        last_id = 0

        while True:

            rows = plugin_result_repository.stream_batch_by_investigation(
                investigation_id,
                after_id=last_id,
                limit=self._batch_size,
            )

            if not rows:
                break

            last_id = rows[-1].id

            batch_ids: list[str] = []
            batch_documents: list[str] = []
            batch_metadatas: list[dict] = []
            batch_hashes: list[str] = []
            batch_evidence_ids: list[int] = []

            for row in rows:

                evidence_id = row.id
                seen_ids.add(evidence_id)

                plugin_name = (
                    row.plugin_name
                    if row.plugin_name
                    else row.artifact_name
                )

                document = self._embedding_manager.build_document({
                    "artifact_name": row.artifact_name,
                    "artifact_type": row.artifact_type,
                    "artifact_value": row.artifact_value,
                })

                content_hash = hashlib.sha256(
                    document.encode("utf-8")
                ).hexdigest()

                # Unchanged evidence is already indexed: skip it entirely.
                if state_map.get(evidence_id) == content_hash:
                    continue

                batch_ids.append(f"ev-{evidence_id}")
                batch_documents.append(document)
                batch_evidence_ids.append(evidence_id)
                batch_hashes.append(content_hash)
                batch_metadatas.append({
                    "investigation_id": investigation_id,
                    "plugin_name": plugin_name,
                    "artifact_type": row.artifact_type,
                    "evidence_id": evidence_id,
                    "confidence_score": row.confidence_score,
                })

            if batch_ids:

                batch_embeddings = (
                    self._embedding_manager.embed_documents(
                        batch_documents
                    )
                )

                # Idempotent write: exactly one vector per evidence id even
                # if a previous run wrote the batch but never committed state.
                self._vector_store.upsert_documents(
                    ids=batch_ids,
                    documents=batch_documents,
                    embeddings=batch_embeddings,
                    metadatas=batch_metadatas,
                )

                state_repository.upsert_many(
                    investigation_id,
                    batch_evidence_ids,
                    batch_hashes,
                )

                newly_indexed += len(batch_ids)

                logger.info(
                    "Indexing page through evidence id %d for "
                    "investigation '%s' (%d new).",
                    last_id,
                    investigation_id,
                    len(batch_ids),
                )

            if len(rows) < self._batch_size:
                break

        removed = self._cleanup_stale_state(
            session,
            state_repository,
            investigation_id,
            state_map,
            seen_ids,
        )

        logger.info(
            "Indexed %d new evidence records for investigation '%s' "
            "(%d total, %d stale removed).",
            newly_indexed,
            investigation_id,
            total,
            removed,
        )

        return {
            "indexed": newly_indexed,
            "total": total,
            "removed": removed,
        }

    # ------------------------------------------------------------------
    # Stale vector cleanup
    # ------------------------------------------------------------------

    def _cleanup_stale_state(
        self,
        session: Session,
        state_repository: EvidenceIndexStateRepository,
        investigation_id: str,
        state_map: dict[int, str],
        seen_ids: set[int],
    ) -> int:
        """
        Remove index state and vectors for evidence rows that no longer exist.

        SQLite is authoritative: any state row whose evidence id was not
        encountered while streaming the investigation's current evidence set
        is stale and is purged from both the vector store and the state table.
        """

        stale_ids = [
            evidence_id
            for evidence_id in state_map
            if evidence_id not in seen_ids
        ]

        if not stale_ids:
            return 0

        for start in range(0, len(stale_ids), self._batch_size):

            chunk = stale_ids[start : start + self._batch_size]

            self._vector_store.delete_documents(
                [f"ev-{evidence_id}" for evidence_id in chunk]
            )

            state_repository.delete_by_evidence_ids(chunk)

        logger.info(
            "Removed %d stale index entries for investigation '%s'.",
            len(stale_ids),
            investigation_id,
        )

        return len(stale_ids)


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
    "INDEXING_BATCH_SIZE",
    "CHROMA_MAX_BATCH_SIZE",
]