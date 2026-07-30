"""
Embedding Manager for the AI Memory Forensic Investigation Assistant.

Responsible for generating vector embeddings from normalized
forensic evidence using SentenceTransformers.

Author:
    FIA Development Team
"""

from __future__ import annotations

from typing import Final

from sentence_transformers import SentenceTransformer

from app.core.logging import get_logger

logger = get_logger(__name__)

# ==============================================================================
# Constants
# ==============================================================================

DEFAULT_EMBEDDING_MODEL: Final[str] = "all-MiniLM-L6-v2"


# ==============================================================================
# Embedding Manager
# ==============================================================================


class EmbeddingManager:
    """
    Generates embeddings for forensic evidence.
    """

    def __init__(
        self,
        model_name: str = DEFAULT_EMBEDDING_MODEL,
    ) -> None:

        logger.info(
            "Loading embedding model: %s",
            model_name,
        )

        self._model = SentenceTransformer(model_name)

        logger.info(
            "Embedding model loaded successfully."
        )

    # ------------------------------------------------------------------

    @property
    def model(self) -> SentenceTransformer:
        """
        Return embedding model.
        """

        return self._model

    # ------------------------------------------------------------------

    def embed_text(
        self,
        text: str,
    ) -> list[float]:
        """
        Generate an embedding for a single text.

        Parameters
        ----------
        text : str
            Input text.

        Returns
        -------
        list[float]
            Embedding vector.
        """

        embedding = self._model.encode(
            text,
            convert_to_numpy=True,
            normalize_embeddings=True,
        )

        logger.debug(
            "Generated embedding for one document."
        )

        return embedding.tolist()

    # ------------------------------------------------------------------

    def embed_documents(
        self,
        documents: list[str],
    ) -> list[list[float]]:
        """
        Generate embeddings for multiple documents.

        Parameters
        ----------
        documents : list[str]
            Documents to embed.

        Returns
        -------
        list[list[float]]
            Embedding vectors.
        """

        embeddings = self._model.encode(
            documents,
            convert_to_numpy=True,
            normalize_embeddings=True,
        )

        logger.info(
            "Generated embeddings for %d documents.",
            len(documents),
        )

        return embeddings.tolist()

    # ------------------------------------------------------------------

    def build_document(
        self,
        evidence: dict,
    ) -> str:
        """
        Convert normalized evidence into a searchable document.

        Parameters
        ----------
        evidence : dict

        Returns
        -------
        str
        """

        lines: list[str] = []

        for key, value in evidence.items():

            if value is None:
                continue

            lines.append(f"{key}: {value}")

        return "\n".join(lines)

    # ------------------------------------------------------------------

    def embed_evidence(
        self,
        evidence: dict,
    ) -> list[float]:
        """
        Generate an embedding from normalized evidence.
        """

        document = self.build_document(evidence)

        return self.embed_text(document)

    # ------------------------------------------------------------------

    def embed_evidence_batch(
        self,
        evidence_list: list[dict],
    ) -> list[list[float]]:
        """
        Generate embeddings for multiple evidence objects.
        """

        documents = [
            self.build_document(item)
            for item in evidence_list
        ]

        return self.embed_documents(documents)