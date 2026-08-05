"""
AI Investigation Service for the AI Memory Forensic Investigation Assistant.

Answers investigator questions using evidence retrieved from ChromaDB
and the configured Ollama LLM, reusing the existing RAG components.

Author:
    FIA Development Team
"""

from __future__ import annotations

from app.core.logging import get_logger
from app.llm.llm_manager import LLMManager
from app.llm.prompt_builder import PromptBuilder
from app.llm.response_parser import ResponseParser
from app.services.rag.rag_pipeline import RAGPipeline, rag_pipeline

logger = get_logger(__name__)


class AIInvestigationService:
    """
    Coordinates evidence retrieval, prompt construction, LLM inference,
    and response parsing for evidence-backed forensic answers.
    """

    def __init__(
        self,
        rag_pipeline_instance: RAGPipeline | None = None,
        llm_manager: LLMManager | None = None,
        prompt_builder: PromptBuilder | None = None,
        response_parser: ResponseParser | None = None,
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

    # ------------------------------------------------------------------
    # Question Answering
    # ------------------------------------------------------------------

    def _build_references(
        self,
        matches: list[dict],
    ) -> list[dict]:
        """
        Convert ranked retrieval matches into evidence references.
        """

        references: list[dict] = []

        for index, match in enumerate(matches):

            metadata = match.get("metadata") or {}

            references.append({
                "index": index + 1,
                "evidence_id": metadata.get("evidence_id"),
                "plugin_name": metadata.get("plugin_name"),
                "artifact_type": metadata.get("artifact_type"),
                "confidence_score": metadata.get("confidence_score"),
                "document": match.get("document", ""),
                "score": match.get("score"),
            })

        return references

    @staticmethod
    def _retrieval_confidence(
        references: list[dict],
    ) -> int:
        """
        Derive a confidence value from the retrieved evidence scores.
        """

        scores = [
            reference["score"]
            for reference in references
            if reference["score"] is not None
        ]

        if not scores:
            return 50

        return max(
            0,
            min(100, int(round(max(scores) * 100))),
        )

    def answer(
        self,
        investigation_id: str,
        question: str,
        top_k: int = 6,
    ) -> dict:
        """
        Produce an evidence-backed answer for an investigator question.

        Workflow
        --------
        1. Retrieve relevant evidence via semantic search.
        2. Build a context-aware prompt.
        3. Query the configured LLM.
        4. Parse the answer, citations, and confidence.

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

        matches = self._rag_pipeline.search_evidence(
            question=question,
            top_k=top_k,
            investigation_id=investigation_id,
        )

        references = self._build_references(matches)

        if not references:

            logger.info(
                "No indexed evidence found for investigation '%s'.",
                investigation_id,
            )

            return {
                "question": question,
                "answer": (
                    "The answer cannot be determined from the available "
                    "evidence. No indexed evidence was found for this "
                    "investigation."
                ),
                "confidence": 0,
                "insufficient": True,
                "citations": [],
                "references": [],
            }

        evidence_lines = [
            f"[{reference['index']}] {reference['document']}"
            for reference in references
        ]

        context = "\n\n".join(evidence_lines)

        prompt = self._prompt_builder.build_answer_prompt(
            question=question,
            context=context,
        )

        raw_answer = self._llm_manager.generate(
            prompt=prompt,
        )

        parsed = self._response_parser.parse_answer(
            raw_answer,
            len(references),
        )

        citations = [
            number
            for number in parsed["citations"]
            if 1 <= number <= len(references)
        ]

        citation_references = [
            references[number - 1]
            for number in citations
        ]

        if parsed["confidence"] is not None:
            confidence = parsed["confidence"]
        else:
            confidence = self._retrieval_confidence(references)

        insufficient = (
            "cannot be determined from the available evidence"
            in (parsed["answer"] or "").lower()
        )

        logger.info(
            "AI answer produced with %d citations and confidence %d.",
            len(citation_references),
            confidence,
        )

        return {
            "question": question,
            "answer": parsed["answer"],
            "confidence": confidence,
            "insufficient": insufficient,
            "citations": citation_references,
            "references": references,
        }


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
