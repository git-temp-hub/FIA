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
from app.llm.confidence import coverage_cap
from app.llm.prompt_builder import PromptBuilder
from app.services.incident_synthesis import (
    MAX_TIMELINE_EVENTS,
    build_overview,
    build_timeline,
    format_overview,
    format_timeline,
)
from app.services.memory_region_context import malfind_ceiling
from app.services.ioc_matching import (
    format_missing_indicator_set,
    format_network_scan,
    load_indicator_sets,
    match_networks,
    networks_in_question,
)
from app.services.signature_corroboration import (
    assess_signature_matches,
    confidence_ceiling as signature_ceiling,
    corroboration_notice,
    format_corroboration,
)
from app.services.tool_signatures import format_tool_matches, match_tools
from app.services.question_routing import (
    QuestionRoute,
    SourceCoverage,
    assess_coverage,
    format_coverage,
    match_route,
)


class RoutedPromptBuilder:
    """
    Prompt builder that prepends question-routing coverage to the context.

    Wrapping the real builder keeps this concern out of the retrieval
    service, which calls ``build_answer_prompt(question=..., context=...)``
    from three separate answer paths. Only the context is extended, so
    evidence numbering and therefore citation parsing are unaffected.
    """

    def __init__(
        self,
        delegate: PromptBuilder,
        route: QuestionRoute,
        coverage: list[SourceCoverage],
        tool_block: str = "",
        signature_block: str = "",
        ioc_block: str = "",
        synthesis_blocks: list[str] | None = None,
    ) -> None:
        self._delegate = delegate
        self._route = route
        self._coverage = coverage
        self._tool_block = tool_block
        self._signature_block = signature_block
        self._ioc_block = ioc_block
        self._synthesis_blocks = synthesis_blocks or []

    def build_answer_prompt(self, question: str, context: str) -> str:

        sections: list[str] = []

        if self._route.out_of_scope:
            sections.append(
                "EVIDENCE COVERAGE FOR THIS QUESTION\n"
                f"Question type: {self._route.qid} — {self._route.summary}\n\n"
                f"OUT OF SCOPE: {self._route.out_of_scope}\n"
                "State plainly that this platform cannot answer the question "
                "and say what evidence would be required. Do not assemble an "
                "answer from unrelated artifacts."
            )

        else:
            # Sequential rather than exclusive: a synthesis question carries
            # its own blocks and a coverage report, and Q12 carries both an
            # indicator block and a signature block.
            if self._synthesis_blocks:
                sections.extend(self._synthesis_blocks)
            if self._ioc_block:
                sections.append(self._ioc_block)
            if self._tool_block:
                sections.append(self._tool_block)
            if self._signature_block:
                sections.append(self._signature_block)
            if self._coverage:
                sections.append(
                    format_coverage(self._route, self._coverage)
                )

        if not sections:
            return self._delegate.build_answer_prompt(
                question=question,
                context=context,
            )

        return self._delegate.build_answer_prompt(
            question=question,
            context="\n\n".join(sections) + "\n\n" + context,
        )
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

# A synthesis answer needs breadth across plugins, not depth in one. Sized
# to leave room for the overview and timeline blocks inside the 8192-token
# context window.
SYNTHESIS_TOP_K = 14


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

        # Route the question to its authoritative plugins, when it is one of
        # the known question types. Retrieval is then scoped to those
        # plugins, and the prompt is told which expected sources were
        # actually searched so the model cannot report an unsearched source
        # as an absence of activity.
        route = match_route(question)

        scoped_plugins: tuple[str, ...] | None = None
        coverage: list[SourceCoverage] = []
        pinned_ids: tuple[int, ...] = ()
        tool_block = ""
        signature_block = ""
        signature_assessment = None
        synthesis_blocks: list[str] = []
        ioc_block = ""
        prompt_builder = self._prompt_builder

        if route is not None:

            coverage = assess_coverage(db, investigation_id, route.plugins)

            if route.plugins:
                usable = tuple(
                    entry.plugin for entry in coverage if entry.usable
                )
                scoped_plugins = usable or None

            if route.tool_scan:
                matches = match_tools(db, investigation_id)
                tool_block = format_tool_matches(matches)
                # Pin the matched rows so the scan's findings arrive as
                # numbered, citable evidence rather than an unsupportable
                # assertion in the preamble.
                pinned_ids = tuple(
                    identifier
                    for entry in matches
                    for identifier in entry.evidence_ids[:3]
                )

            if route.ioc_check:
                ioc_block, ioc_ids = self._correlate_indicators(
                    db, investigation_id, question, route
                )
                pinned_ids = pinned_ids + ioc_ids

            if route.synthesis:
                synthesis_blocks, breadth = self._build_synthesis(
                    db, investigation_id
                )
                # A whole-incident conclusion cannot rest on six rows from
                # one plugin: retrieval is widened across every plugin that
                # produced evidence.
                scoped_plugins = breadth or scoped_plugins
                top_k = max(top_k, SYNTHESIS_TOP_K)

            if route.signature_check:
                signature_assessment = assess_signature_matches(
                    db, investigation_id
                )
                signature_block = format_corroboration(signature_assessment)

            prompt_builder = RoutedPromptBuilder(
                delegate=self._prompt_builder,
                route=route,
                coverage=coverage,
                tool_block=tool_block,
                signature_block=signature_block,
                ioc_block=ioc_block,
                synthesis_blocks=synthesis_blocks,
            )

        result = answer_with_evidence_fallback(
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
                plugins=scoped_plugins,
                pinned_ids=pinned_ids,
            ),
            llm_generate=self._llm_manager.generate,
            prompt_builder=prompt_builder,
            response_parser=self._response_parser,
            lazy_index=lambda: self._maybe_lazy_index(investigation_id),
        )

        # Confidence ceilings enforced after the answer is produced, so they
        # hold whatever the model wrote. Applied here rather than inside the
        # retrieval service, which is deliberately unaware of routing.
        ceilings: list[int] = []

        # A source that was never searched cannot support a confident answer.
        if route is not None and coverage:
            cap = coverage_cap(
                sum(1 for entry in coverage if not entry.usable),
                len(coverage),
            )
            if cap is not None:
                ceilings.append(cap)

        # An answer resting only on mapped (JIT-typical) malfind regions is
        # not a confident detection, however the row is labelled. Read from
        # the cited references so it applies on every path, routed or not.
        malfind_cap = malfind_ceiling(result.get("citations") or [])

        if malfind_cap is not None:
            ceilings.append(malfind_cap)

        if signature_assessment is not None:
            # Enforced in code rather than requested in the prompt: asked to
            # triage matches sitting inside Defender's memory, the model
            # reported the malware as present in three of four runs at
            # temperature 0.0.
            cap = signature_ceiling(signature_assessment)
            if cap is not None:
                ceilings.append(cap)

            notice = corroboration_notice(signature_assessment)
            if notice:
                result["answer"] = f"{result.get('answer') or ''}\n{notice}"

        if ceilings and result.get("confidence") is not None:
            result["confidence"] = min(result["confidence"], *ceilings)

        return result

    # ------------------------------------------------------------------
    # Indicator correlation
    # ------------------------------------------------------------------

    def _correlate_indicators(
        self,
        db: Session,
        investigation_id: str,
        question: str,
        route: QuestionRoute,
    ) -> tuple[str, tuple[int, ...]]:
        """
        Correlate collected network evidence against supplied indicators.

        Indicators come from the investigator's question and from
        department-supplied sets. When a route names an actor whose set has
        not been supplied, attribution is refused rather than guessed at.
        """

        networks = list(networks_in_question(question))
        supplied = load_indicator_sets()

        for indicator_set in supplied:
            networks.extend(indicator_set.networks)

        if route.requires_indicator_set and not supplied:
            return (
                format_missing_indicator_set(route.requires_indicator_set),
                (),
            )

        scan = match_networks(db, investigation_id, tuple(networks))

        # Matching rows are pinned so the addresses are citable: a matched
        # connection is one row among hundreds and would not otherwise rank
        # into the retrieved sample.
        return format_network_scan(scan), scan.evidence_ids[:6]

    # ------------------------------------------------------------------
    # Integrated assessment
    # ------------------------------------------------------------------

    def _build_synthesis(
        self,
        db: Session,
        investigation_id: str,
    ) -> tuple[list[str], tuple[str, ...]]:
        """
        Build the corpus overview and timeline for an integrated assessment.

        Returns the prompt blocks and the plugins that actually produced
        evidence, so retrieval can be widened across all of them.
        """

        overview = build_overview(db, investigation_id)
        timeline = build_timeline(db, investigation_id)

        blocks = [
            format_overview(overview),
            format_timeline(timeline, MAX_TIMELINE_EVENTS),
            (
                "HOW TO ANSWER THIS QUESTION\n"
                "This is an integrated assessment, not a single-artifact "
                "lookup. Use the CORPUS OVERVIEW for any statement about "
                "scale -- those counts are exact and cover every record, "
                "whereas the numbered evidence below is a sample. Use the "
                "INCIDENT TIMELINE for ordering, and do not assert a sequence "
                "the timeline does not show.\n\n"
                "Write FINDING as a short narrative of what the evidence "
                "supports, in order where order is known. Keep the four "
                "sections and the final CONFIDENCE line exactly as specified. "
                "Cite records for specific claims; cite nothing for the "
                "overview counts and say they come from the corpus "
                "overview.\n\n"
                "A conclusion of 'no malicious activity' is a strong claim "
                "about the whole host. Make it only if the overview and "
                "timeline support it, and state which areas were not "
                "examined. Equally, do not escalate: a large count in one "
                "plugin is not by itself an incident."
            ),
        ]

        return blocks, overview.completed_plugins

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