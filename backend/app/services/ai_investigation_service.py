"""
AI Investigation Service for the AI Memory Forensic Investigation Assistant.

Answers investigator questions using evidence retrieved from ChromaDB
plus the configured Ollama LLM, reusing the existing RAG components.

Evidence source of truth
------------------------
``plugin_results`` (SQLite) is authoritative. When ChromaDB returns no vectors
for an investigation, the service NEVER concludes there is no evidence: it
consults SQLite first and, when records exist, answers from a deterministic
entity-first fallback before triggering lazy indexing.

Author:
    FIA Development Team
"""

from __future__ import annotations

import threading

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.repositories import PluginResultRepository
from app.llm.llm_manager import LLMManager
from app.llm.prompt_builder import PromptBuilder
from app.llm.response_parser import ResponseParser
from app.services.forensic_evidence_retrieval_service import (
    ForensicEvidenceRetrievalService,
    NO_EVIDENCE_COPY,
    answer_with_evidence_fallback,
    build_references,
    forensic_evidence_retrieval_service,
    generate_answer_from_references,
)
from app.services.rag.rag_pipeline import RAGPipeline, rag_pipeline

logger = get_logger(__name__)


class AIInvestigationService:
    """
    Coordinates evidence retrieval, prompt construction, LLM inference,
    and response parsing for evidence-backed forensic answers.

    Orchestrades two evidence paths:

    * primary: semantic search over the ChromaDB vector store;
    * fallback: deterministic SQLite retrieval (authoritative).
    """

    def __init__(
        self,
        rag_pipeline_instance: RAGPipeline | None = None,
        llm_manager: LLMManager | None = None,
        prompt_builder: PromptBuilder | None = None,
        response_parser: ResponseParser | None = None,
        forensic_retrieval: ForensicEvidenceRetrievalService | None = None,
    ) -> None:

        self._rag_pipeline = (
            rag_pipeline_instance
            if rag_pipeline_instance is not None
            else rag_pipeline
        )

        self._llm_manager = (
            llm_manager
            if llm_manager is not None
            else self._rag_pipeline.llm_manager
        )

        self._prompt_builder = (
            prompt_builder
            if prompt_builder is not None
            else PromptBuilder()
        )

        self._response_parser = (
            response_parser
            if response_parser is not None
            else ResponseParser()
        )

        self._forensic_retrieval = (
            forensic_retrieval
            if forensic_retrieval is not None
            else forensic_evidence_retrieval_service
        )

        # Investigations already scheduled for lazy indexing in this process.
        self._lazy_indexed: set[str] = set()

        logger.info(
            "AI Investigation Service initialized."
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def rag_pipeline(self) -> RAGPipeline:
        return self._rag_pipeline

    @property
    def llm_manager(self) -> LLMManager:
        return self._llm_manager

    @property
    def prompt_builder(self) -> PromptBuilder:
        return self._prompt_builder

    @property
    def response_parser(self) -> ResponseParser:
        return self._response_parser

    @property
    def forensic_retrieval(self) -> ForensicEvidenceRetrievalService:
        return self._forensic_retrieval

    # ------------------------------------------------------------------
    # Question Answering
    # ------------------------------------------------------------------

    def _semantic_search(
        self,
        investigation_id: str,
        question: str,
        top_k: int,
    ) -> list[dict]:
        """Run the ChromaDB semantic search for one investigation."""

        return self._rag_pipeline.search_evidence(
            question=question,
            top_k=top_k,
            investigation_id=investigation_id,
        )

    def answer(
        self,
        investigation_id: str,
        question: str,
        top_k: int = 6,
        db: Session | None = None,
    ) -> dict:
        """
        Produce an evidence-backed answer for an investigator question.

        When a database session is supplied (chat route), an empty vector
        result is treated as "index missing", not "evidence missing": SQLite
        is consulted and the question is answered from it when records exist.

        Parameters
        ----------
        investigation_id : str

        question : str

        top_k : int

        db : Session | None
            Active database session. When ``None``, only the semantic path
            is available and no evidence claims are made from an empty index.

        Returns
        -------
        dict
            {
                "question": str,
                "answer": str,
                "confidence": int,
                "insufficient": bool,
                "citations": list[dict],
                "references": list[dict],
            }
        """

        if db is None:
            return self.answer_semantic_only(
                investigation_id,
                question,
                top_k,
            )

        return answer_with_evidence_fallback(
            investigation_id=investigation_id,
            question=question,
            top_k=top_k,
            db=db,
            semantic_search=lambda q, k: self._semantic_search(
                investigation_id,
                q,
                k,
            ),
            count_evidence=lambda: PluginResultRepository(
                db
            ).count_by_investigation(investigation_id),
            fallback_retrieve=lambda q, k: self._forensic_retrieval.retrieve(
                session=db,
                investigation_id=investigation_id,
                question=q,
                top_k=k,
            ),
            llm_generate=self._llm_manager.generate,
            prompt_builder=self._prompt_builder,
            response_parser=self._response_parser,
            lazy_index=lambda: self._maybe_lazy_index(investigation_id),
        )

    def answer_semantic_only(
        self,
        investigation_id: str,
        question: str,
        top_k: int = 6,
    ) -> dict:
        """
        Answer strictly from the vector store (no database session available).

        An empty index here never claims "no evidence" — the revised copy only
        states that no records could be consulted.
        """

        try:
            matches = self._semantic_search(
                investigation_id,
                question,
                top_k,
            )
        except Exception as exc:
            logger.warning(
                "[CHAT] semantic search failed for investigation '%s': %s",
                investigation_id,
                exc,
            )
            matches = []

        references = build_references(matches)

        if not references:
            logger.info(
                "[CHAT] no semantic evidence for investigation '%s'.",
                investigation_id,
            )
            return {
                "question": question,
                "answer": NO_EVIDENCE_COPY,
                "confidence": 0,
                "insufficient": True,
                "citations": [],
                "references": [],
            }

        return generate_answer_from_references(
            question,
            references,
            self._llm_manager.generate,
            self._prompt_builder,
            self._response_parser,
        )

    # ------------------------------------------------------------------
    # Lazy Indexing
    # ------------------------------------------------------------------

    def _maybe_lazy_index(
        self,
        investigation_id: str,
    ) -> None:
        """
        Kick off a background index once per investigation per process.

        Called only after a SQLite fallback has answered (i.e. evidence exists
        but ChromaDB holds no vectors). Runs on a daemon thread so the chat
        response is never blocked; failures are logged and swallowed.
        """

        if investigation_id in self._lazy_indexed:
            return

        self._lazy_indexed.add(investigation_id)

        logger.info(
            "[CHAT] lazy indexing triggered for investigation '%s'.",
            investigation_id,
        )

        def _run() -> None:
            try:
                from app.database.database import SessionLocal
                from app.services.rag.indexing_service import (
                    rag_indexing_service,
                )

                with SessionLocal() as session:
                    rag_indexing_service.index_investigation(
                        investigation_id,
                        session,
                    )

                logger.info(
                    "[CHAT] lazy indexing completed for investigation '%s'.",
                    investigation_id,
                )
            except Exception as exc:
                logger.warning(
                    "[CHAT] lazy indexing failed for investigation '%s': %s",
                    investigation_id,
                    exc,
                )

        thread = threading.Thread(
            target=_run,
            name=f"lazy-index-{investigation_id}",
            daemon=True,
        )
        thread.start()


# ==============================================================================
# Singleton Instance
# ==============================================================================

ai_investigation_service = AIInvestigationService()


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "AIInvestigationService",
    "ai_investigation_service",
]