"""
Vector Store for the AI Memory Forensic Investigation Assistant.

Provides ChromaDB persistence and retrieval for forensic evidence.

Author:
    FIA Development Team
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import chromadb
from chromadb.api.models.Collection import Collection

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# ==============================================================================
# Constants
# ==============================================================================

DEFAULT_COLLECTION_NAME: Final[str] = "fia_memory_evidence"


# ==============================================================================
# Vector Store
# ==============================================================================


class VectorStore:
    """
    ChromaDB wrapper.
    """

    def __init__(
        self,
        collection_name: str = DEFAULT_COLLECTION_NAME,
    ) -> None:

        self._db_path = Path(settings.storage.vectors)

        self._db_path.mkdir(
            parents=True,
            exist_ok=True,
        )

        logger.info(
            "Initializing ChromaDB at %s",
            self._db_path,
        )

        self._client = chromadb.PersistentClient(
            path=str(self._db_path)
        )

        self._collection = self._client.get_or_create_collection(
            name=collection_name,
        )

        logger.info(
            "Vector collection '%s' ready.",
            collection_name,
        )

    # ------------------------------------------------------------------

    @property
    def client(self):
        return self._client

    @property
    def collection(self) -> Collection:
        return self._collection

    # ------------------------------------------------------------------

    def add_document(
        self,
        document_id: str,
        document: str,
        embedding: list[float],
        metadata: dict,
    ) -> None:
        """
        Store a single document in ChromaDB.
        """

        self._collection.add(
            ids=[document_id],
            documents=[document],
            embeddings=[embedding],
            metadatas=[metadata],
        )

        logger.info(
            "Stored document: %s",
            document_id,
        )

    # ------------------------------------------------------------------

    def add_documents(
        self,
        ids: list[str],
        documents: list[str],
        embeddings: list[list[float]],
        metadatas: list[dict],
    ) -> None:
        """
        Store multiple forensic documents.
        """

        self._collection.add(
            ids=ids,
            documents=documents,
            embeddings=embeddings,
            metadatas=metadatas,
        )

        logger.info(
            "Stored %d documents.",
            len(ids),
        )
    # ------------------------------------------------------------------

    def upsert_documents(
        self,
        ids: list[str],
        documents: list[str],
        embeddings: list[list[float]],
        metadatas: list[dict],
    ) -> None:
        """
        Insert or update multiple forensic documents.

        Idempotent by design: re-writing an existing document id replaces the
        vector instead of raising, so a re-run after an interrupted index
        cannot create duplicate vectors for the same evidence id.
        """

        self._collection.upsert(
            ids=ids,
            documents=documents,
            embeddings=embeddings,
            metadatas=metadatas,
        )

        logger.info(
            "Upserted %d documents.",
            len(ids),
        )
    # ------------------------------------------------------------------

    def search(
        self,
        embedding: list[float],
        limit: int = 5,
        where: dict | None = None,
    ) -> dict:
        """
        Perform similarity search.

        Parameters
        ----------
        embedding : list[float]

        limit : int

        where : dict | None
            Optional ChromaDB metadata filter.
        """

        logger.info(
            "Searching top %d similar documents.",
            limit,
        )

        query_kwargs = {
            "query_embeddings": [embedding],
            "n_results": limit,
        }

        if where:
            query_kwargs["where"] = where

        return self._collection.query(
            **query_kwargs,
        )

    # ------------------------------------------------------------------

    def get_by_metadata(
        self,
        where: dict,
    ) -> list[str]:
        """
        Return the ids of documents matching a metadata filter.
        """

        return self._collection.get(
            where=where,
        )["ids"]

    # ------------------------------------------------------------------

    def delete_by_metadata(
        self,
        where: dict,
    ) -> int:
        """
        Delete every document matching a metadata filter.

        Returns the number of deleted documents.
        """

        matching_ids = self.get_by_metadata(where)

        if matching_ids:
            self._collection.delete(
                where=where,
            )

        logger.info(
            "Deleted %d documents matching metadata filter.",
            len(matching_ids),
        )

        return len(matching_ids)

    # ------------------------------------------------------------------

    def delete_document(
        self,
        document_id: str,
    ) -> None:
        """
        Delete one document.
        """

        self._collection.delete(
            ids=[document_id],
        )

        logger.info(
            "Deleted document: %s",
            document_id,
        )

    # ------------------------------------------------------------------

    def delete_documents(
        self,
        document_ids: list[str],
    ) -> int:
        """
        Delete several documents by id.

        Returns the number of document ids passed in; ChromaDB's delete is
        idempotent so ids that are already absent are silently skipped.
        """

        if not document_ids:
            return 0

        self._collection.delete(
            ids=document_ids,
        )

        logger.info(
            "Deleted %d documents.",
            len(document_ids),
        )

        return len(document_ids)

    # ------------------------------------------------------------------

    def count(self) -> int:
        """
        Return number of stored documents.
        """

        return self._collection.count()

    # ------------------------------------------------------------------

    def reset_collection(self) -> None:
        """
        Remove every stored document.
        """

        ids = self._collection.get()["ids"]

        if ids:
            self._collection.delete(ids=ids)

        logger.warning(
            "Vector collection cleared."
        )