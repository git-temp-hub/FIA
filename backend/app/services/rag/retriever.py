"""
Retriever for the AI Memory Forensic Investigation Assistant.

Retrieves the most relevant forensic evidence from ChromaDB.

Author:
    FIA Development Team
"""

from __future__ import annotations

from typing import Final

from app.core.logging import get_logger
from app.services.rag.embedding_manager import EmbeddingManager
from app.services.rag.vector_store import VectorStore

logger = get_logger(__name__)

DEFAULT_TOP_K: Final[int] = 5


class Retriever:
    """
    Retrieves forensic evidence from the vector database.
    """

    def __init__(
        self,
        embedding_manager: EmbeddingManager | None = None,
        vector_store: VectorStore | None = None,
    ) -> None:

        self._embedding_manager = (
            embedding_manager
            if embedding_manager
            else EmbeddingManager()
        )

        self._vector_store = (
            vector_store
            if vector_store
            else VectorStore()
        )

        logger.info(
            "Retriever initialized."
        )

    # ------------------------------------------------------------------

    @property
    def embedding_manager(self) -> EmbeddingManager:
        return self._embedding_manager

    @property
    def vector_store(self) -> VectorStore:
        return self._vector_store

    # ------------------------------------------------------------------

    def retrieve(
        self,
        question: str,
        top_k: int = DEFAULT_TOP_K,
        where: dict | None = None,
    ) -> dict:
        """
        Retrieve the most relevant forensic evidence.

        Parameters
        ----------
        question : str
            Investigator question.

        top_k : int
            Number of documents to retrieve.

        where : dict | None
            Optional ChromaDB metadata filter.

        Returns
        -------
        dict
            ChromaDB query result.
        """

        logger.info(
            "Retrieving evidence for question: %s",
            question,
        )

        query_embedding = self._embedding_manager.embed_text(
            question
        )

        return self._vector_store.search(
            embedding=query_embedding,
            limit=top_k,
            where=where,
        )

    # ------------------------------------------------------------------

    def retrieve_by_investigation(
        self,
        question: str,
        investigation_id: str,
        top_k: int = DEFAULT_TOP_K,
    ) -> dict:
        """
        Retrieve evidence restricted to a single investigation.
        """

        return self.retrieve(
            question=question,
            top_k=top_k,
            where={"investigation_id": investigation_id},
        )

    # ------------------------------------------------------------------

    def retrieve_ranked(
        self,
        question: str,
        top_k: int = DEFAULT_TOP_K,
        where: dict | None = None,
    ) -> list[dict]:
        """
        Retrieve evidence as a ranked list with document, metadata,
        and similarity score.
        """

        result = self.retrieve(
            question=question,
            top_k=top_k,
            where=where,
        )

        ids = result.get("ids", [[]])[0]
        documents = result.get("documents", [[]])[0]
        metadatas = result.get("metadatas", [[]])[0]
        distances = result.get("distances", [[]])[0]

        ranked: list[dict] = []

        for index, document_id in enumerate(ids):

            distance = (
                distances[index]
                if index < len(distances)
                else None
            )

            ranked.append({
                "id": document_id,
                "document": (
                    documents[index]
                    if index < len(documents)
                    else ""
                ),
                "metadata": (
                    metadatas[index]
                    if index < len(metadatas)
                    else {}
                ),
                "distance": distance,
                "score": (
                    round(1.0 / (1.0 + distance), 4)
                    if distance is not None
                    else None
                ),
            })

        logger.info(
            "Retrieved %d ranked documents.",
            len(ranked),
        )

        return ranked

    # ------------------------------------------------------------------

    def retrieve_documents(
        self,
        question: str,
        top_k: int = DEFAULT_TOP_K,
    ) -> list[str]:
        """
        Retrieve only document text.
        """

        result = self.retrieve(
            question=question,
            top_k=top_k,
        )

        return result.get("documents", [[]])[0]

    # ------------------------------------------------------------------

    def retrieve_metadata(
        self,
        question: str,
        top_k: int = DEFAULT_TOP_K,
    ) -> list[dict]:
        """
        Retrieve only metadata.
        """

        result = self.retrieve(
            question=question,
            top_k=top_k,
        )

        return result.get("metadatas", [[]])[0]

    # ------------------------------------------------------------------

    def build_context(
        self,
        documents: list[str],
    ) -> str:
        """
        Build a context string from retrieved documents.

        Parameters
        ----------
        documents : list[str]

        Returns
        -------
        str
        """

        if not documents:
            return ""

        return "\n\n".join(documents)

    # ------------------------------------------------------------------

    def retrieve_context(
        self,
        question: str,
        top_k: int = DEFAULT_TOP_K,
    ) -> str:
        """
        Retrieve evidence and build an LLM-ready context.

        Parameters
        ----------
        question : str

        top_k : int

        Returns
        -------
        str
        """

        documents = self.retrieve_documents(
            question=question,
            top_k=top_k,
        )

        context = self.build_context(documents)

        logger.info(
            "Context built with %d retrieved documents.",
            len(documents),
        )

        return context