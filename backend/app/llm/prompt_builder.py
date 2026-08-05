"""
Prompt Builder for the AI Memory Forensic Investigation Assistant.

Constructs LLM prompts for evidence-backed forensic question answering.

Author:
    FIA Development Team
"""

from __future__ import annotations

from app.core.logging import get_logger

logger = get_logger(__name__)


class PromptBuilder:
    """
    Builds structured prompts for the forensic LLM.
    """

    def __init__(self) -> None:
        logger.info(
            "Prompt Builder initialized."
        )

    # ------------------------------------------------------------------
    # Answer Prompt
    # ------------------------------------------------------------------

    def build_answer_prompt(
        self,
        question: str,
        context: str,
    ) -> str:
        """
        Build a context-aware question answering prompt.

        The prompt instructs the model to answer exclusively from the
        numbered evidence, cite supporting evidence by number, and state
        when the evidence is insufficient.

        Parameters
        ----------
        question : str

        context : str
            Numbered forensic evidence blocks.
        """

        return f"""
You are an expert Digital Memory Forensics Investigator.

Answer the investigator's question using ONLY the numbered forensic evidence below.

RULES
- Base every claim on the evidence and reference it with its number, e.g. [1], [2].
- Never invent facts, filenames, PIDs, or network connections that are not present in the evidence.
- If the evidence is insufficient to answer, clearly state: "The answer cannot be determined from the available evidence."
- Do not reference evidence numbers that were not provided.
- End your answer with a line in the exact format: CONFIDENCE: <0-100>

FORENSIC EVIDENCE
=================
{context}

QUESTION
========
{question}

ANSWER
======
""".strip()


# ==============================================================================
# Singleton Instance
# ==============================================================================

prompt_builder = PromptBuilder()


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "PromptBuilder",
    "prompt_builder",
]
