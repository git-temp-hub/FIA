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

    def search(
        self,
        embedding: list[float],
        limit: int = 5,
    ) -> dict:
        """
        Perform similarity search.
        """

        logger.info(
            "Searching top %d similar documents.",
            limit,
        )

        return self._collection.query(
            query_embeddings=[embedding],
            n_results=limit,
        )

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