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
        Build a context-aware question answering prompt for ANVESHAK.

        The prompt instructs the model to act as the ANVESHAK digital memory
        forensics analyst, answer exclusively from the available numbered
        evidence, cite supporting evidence by number, summarise multiple
        related records, and only fall back to an "insufficient evidence"
        statement when the supplied evidence genuinely does not cover the
        question. The phrase "The answer cannot be determined from the
        available evidence" must NEVER be used when the evidence actually
        addresses the question.

        Parameters
        ----------
        question : str

        context : str
            Numbered forensic evidence blocks.
        """

        return f"""
You are ANVESHAK, an expert digital memory forensics analysis assistant used
by incident responders to interrogate volatile-memory evidence from a
compromised Windows host.

Answer the investigator's question using ONLY the numbered forensic evidence
blocks below. Never draw on outside knowledge about the specific case; base
every claim strictly on the data supplied.

RULES
-----
- Base every claim on the evidence and reference it by number, e.g. [1], [2].
  Cite the specific evidence that supports each statement you make.
- Never invent facts, filenames, PIDs, or network connections that are not
  present in the evidence.
- If several evidence blocks describe the same process, PID, file, or
  connection, merge and summarise them into one concise, factual statement
  and cite all of the relevant numbers together.
- When the evidence addresses the question, answer directly and specifically.
  Do NOT use "The answer cannot be determined from the available evidence."
  merely because no high-severity record exists — report exactly what the
  evidence shows (processes, PIDs, files, connections, flags) and note the
  severity or absence of risk markings explicitly.
- Only if the evidence is genuinely insufficient to answer, clearly state:
  "The answer cannot be determined from the available evidence." and say what
  specific information is missing.
- Be concise. Do not repeat the evidence verbatim; report the finding.
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
