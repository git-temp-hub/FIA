"""
RAG Pipeline for the AI Memory Forensic Investigation Assistant.

Coordinates evidence retrieval and LLM inference to produce
evidence-backed forensic answers.

Author:
    FIA Development Team
"""

from __future__ import annotations

from app.core.logging import get_logger
from app.llm.llm_manager import LLMManager
from app.rag.retriever import Retriever

logger = get_logger(__name__)


class RAGPipeline:
    """
    End-to-end Retrieval-Augmented Generation pipeline.

    This class orchestrates the retrieval and language model
    components of the FIA backend. Business logic for question
    answering will be implemented in later iterations.
    """

    def __init__(
        self,
        retriever: Retriever | None = None,
        llm_manager: LLMManager | None = None,
    ) -> None:
        """
        Initialize the RAG pipeline.

        Parameters
        ----------
        retriever : Retriever | None
            Optional Retriever instance.

        llm_manager : LLMManager | None
            Optional LLM manager instance.
        """

        self._retriever = (
            retriever
            if retriever is not None
            else Retriever()
        )

        self._llm_manager = (
            llm_manager
            if llm_manager is not None
            else LLMManager()
        )

        logger.info(
            "RAG Pipeline initialized."
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def retriever(self) -> Retriever:
        """
        Return the configured Retriever.
        """

        return self._retriever

    @property
    def llm_manager(self) -> LLMManager:
        """
        Return the configured LLM manager.
        """

        return self._llm_manager


    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def retrieve(
        self,
        question: str,
        top_k: int = 5,
    ) -> dict:
        """
        Retrieve the most relevant forensic evidence.

        Parameters
        ----------
        question : str
            Investigator question.

        top_k : int
            Number of documents to retrieve.

        Returns
        -------
        dict
            Raw retrieval result.
        """

        logger.info(
            "Retrieving forensic evidence."
        )

        return self.retriever.retrieve(
            question=question,
            top_k=top_k,
        )

    # ------------------------------------------------------------------

    def retrieve_documents(
        self,
        question: str,
        top_k: int = 5,
    ) -> list[str]:
        """
        Retrieve only forensic document text.

        Parameters
        ----------
        question : str

        top_k : int

        Returns
        -------
        list[str]
        """

        return self.retriever.retrieve_documents(
            question=question,
            top_k=top_k,
        )

    # ------------------------------------------------------------------

    def retrieve_metadata(
        self,
        question: str,
        top_k: int = 5,
    ) -> list[dict]:
        """
        Retrieve only forensic metadata.

        Parameters
        ----------
        question : str

        top_k : int

        Returns
        -------
        list[dict]
        """

        return self.retriever.retrieve_metadata(
            question=question,
            top_k=top_k,
        )

    # ------------------------------------------------------------------

    def build_context(
        self,
        question: str,
        top_k: int = 5,
    ) -> str:
        """
        Retrieve evidence and construct an LLM-ready context.

        Parameters
        ----------
        question : str

        top_k : int

        Returns
        -------
        str
            Context constructed from retrieved evidence.
        """

        documents = self.retrieve_documents(
            question=question,
            top_k=top_k,
        )

        context = self.retriever.build_context(
            documents
        )

        logger.info(
            "Context successfully prepared."
        )

        return context


    # ------------------------------------------------------------------
    # Prompt Construction
    # ------------------------------------------------------------------

    def build_prompt(
        self,
        question: str,
        context: str,
    ) -> str:
        """
        Construct an evidence-backed prompt for the LLM.

        Parameters
        ----------
        question : str
            Investigator question.

        context : str
            Retrieved forensic evidence.

        Returns
        -------
        str
            Prompt ready for the language model.
        """

        prompt = f"""
You are an expert Digital Memory Forensics Investigator.

Answer the investigator's question ONLY using the forensic evidence below.

If the evidence does not contain enough information,
clearly state that the answer cannot be determined from the available evidence.

Never invent facts.

==========================
FORENSIC EVIDENCE
==========================

{context}

==========================
QUESTION
==========================

{question}

==========================
ANSWER
==========================
"""

        return prompt.strip()

    # ------------------------------------------------------------------
    # Question Answering
    # ------------------------------------------------------------------

    def answer(
        self,
        question: str,
        top_k: int = 5,
    ) -> dict:
        """
        Execute the complete Retrieval-Augmented Generation pipeline.

        Parameters
        ----------
        question : str

        top_k : int

        Returns
        -------
        dict
            AI answer together with supporting evidence.
        """

        logger.info(
            "Starting RAG pipeline."
        )

        context = self.build_context(
            question=question,
            top_k=top_k,
        )

        prompt = self.build_prompt(
            question=question,
            context=context,
        )

        answer = self.llm_manager.generate(
            prompt=prompt,
        )

        evidence = self.retrieve_documents(
            question=question,
            top_k=top_k,
        )

        metadata = self.retrieve_metadata(
            question=question,
            top_k=top_k,
        )

        logger.info(
            "RAG pipeline completed."
        )

        return {
            "question": question,
            "answer": answer,
            "context": context,
            "evidence": evidence,
            "metadata": metadata,
        }