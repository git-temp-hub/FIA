"""
Response Parser for the AI Memory Forensic Investigation Assistant.

Parses LLM output into a structured answer with a confidence score
and evidence citations.

Author:
    FIA Development Team
"""

from __future__ import annotations

import re

from app.core.logging import get_logger

logger = get_logger(__name__)

_CONFIDENCE_PATTERN = re.compile(
    r"confidences?[:\s]*(\d{1,3})",
    re.IGNORECASE,
)

_CONFIDENCE_LINE_PATTERN = re.compile(
    r"^\s*confidences?[:\s]*\d{1,3}\s*$",
    re.IGNORECASE | re.MULTILINE,
)

# Matches a bracketed citation group: [1], [4,5] or [4, 5]. The grouped form
# appears when the model cites several records for one statement; matching
# only "[digit]" silently dropped every citation after the first in a group.
_CITATION_PATTERN = re.compile(r"\[(\d+(?:\s*,\s*\d+)*)\]")


class ResponseParser:
    """
    Parses forensic LLM responses.
    """

    def __init__(self) -> None:
        logger.info(
            "Response Parser initialized."
        )

    # ------------------------------------------------------------------
    # Answer Parsing
    # ------------------------------------------------------------------

    def parse_answer(
        self,
        raw: str,
        num_evidence: int,
    ) -> dict:
        """
        Parse an LLM answer into structured fields.

        Parameters
        ----------
        raw : str
            Raw LLM output.

        num_evidence : int
            Number of evidence blocks provided in the prompt.

        Returns
        -------
        dict
            {"answer": str, "confidence": int | None, "citations": list[int]}
        """

        if not raw:
            return {
                "answer": "",
                "confidence": None,
                "citations": [],
            }

        text = raw.strip()

        confidence: int | None = None

        match = _CONFIDENCE_PATTERN.search(text)

        if match:
            confidence = max(
                0,
                min(100, int(match.group(1))),
            )

        text = _CONFIDENCE_LINE_PATTERN.sub("", text).strip()

        citations: list[int] = []

        for group in _CITATION_PATTERN.findall(text):

            for token in group.split(","):

                number = int(token.strip())

                if 1 <= number <= num_evidence and number not in citations:
                    citations.append(number)

        logger.info(
            "Parsed answer with %d citations.",
            len(citations),
        )

        return {
            "answer": text,
            "confidence": confidence,
            "citations": citations,
        }


# ==============================================================================
# Singleton Instance
# ==============================================================================

response_parser = ResponseParser()


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "ResponseParser",
    "response_parser",
]
