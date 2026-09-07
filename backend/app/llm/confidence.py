"""
Confidence calibration for forensic answers.

Why this exists
---------------
Confidence was previously derived from ``plugin_results.confidence_score`` via
``retrieval_confidence``. Every row the classifier writes carries the constant
value 100, so that column holds no information: the maximum was always 1.0,
the risk/exactness bonuses pushed past the ceiling, and every answer reported
confidence 100 — including answers whose own ASSESSMENT said "certainty is
moderate" or that rested on a source which never ran.

A number that is always 100 is worse than no number, because a reader takes it
as a claim. This module derives confidence from signals that actually vary:

* the qualitative hedging the model wrote in its own ASSESSMENT section;
* whether the answer cited anything at all;
* the risk level of the evidence actually cited;
* whether every expected source for the question was searched.

Direction of error is deliberate: every rule here can only lower confidence,
never raise it, and the ceiling is 95 rather than 100. A single memory
acquisition does not support a zero-doubt claim, so 100 is not an outcome this
system should ever print.
"""

from __future__ import annotations

import re

from app.core.logging import get_logger

logger = get_logger(__name__)


# ==============================================================================
# Bands
# ==============================================================================

CEILING = 95
"""No forensic finding from one acquisition warrants a zero-doubt claim."""

BAND_STRONG = 85
BAND_MODERATE = 60
BAND_WEAK = 35
BAND_NONE = 15
BAND_UNQUALIFIED = 50
"""Used when the ASSESSMENT contains no recognisable certainty language."""

# Ordered weakest-first: the weakest qualifier present governs. An assessment
# reading "the evidence strongly supports ... certainty is moderate" is a
# moderate-certainty finding; the hedge is the operative half of the sentence.
_BANDS: tuple[tuple[int, tuple[str, ...]], ...] = (
    (
        BAND_NONE,
        (
            "cannot be determined", "cannot be answered", "no supporting evidence",
            "does not support", "unable to assess", "out of scope",
            "no evidence to support",
        ),
    ),
    (
        BAND_WEAK,
        (
            "weak", "limited", "inconclusive", "insufficient", "tentative",
            "speculative", "unclear", "cannot confirm", "cannot be confirmed",
            "cannot rule out", "not confirmed", "low certainty", "minimal",
        ),
    ),
    (
        BAND_MODERATE,
        (
            "moderate", "partial", "uncertain", "uncertainty", "suggests",
            "suggestive", "possible", "possibly", "potential", "plausible",
            "circumstantial", "limits confidence", "may be", "might be",
            "plausibly", "indirect",
        ),
    ),
    (
        BAND_STRONG,
        (
            "strong", "strongly", "conclusive", "definitive", "directly",
            "high certainty", "well supported", "well-supported", "clearly",
            "unambiguous",
        ),
    ),
)

_HEADING = re.compile(
    r"^[\s*#_]*ASSESSMENT[\s*:_-]*$",
    re.IGNORECASE | re.MULTILINE,
)

_NEXT_HEADING = re.compile(
    r"^[\s*#_]*(GAPS|FINDING|EVIDENCE|CONFIDENCE)\b",
    re.IGNORECASE | re.MULTILINE,
)


def extract_assessment(answer: str) -> str:
    """
    Return the ASSESSMENT section of a structured answer, or "".

    Tolerates the markdown decoration models add around headings
    (``**ASSESSMENT**``, ``## ASSESSMENT``).
    """

    if not answer:
        return ""

    match = _HEADING.search(answer)

    if match is None:
        return ""

    rest = answer[match.end():]

    following = _NEXT_HEADING.search(rest)

    return (rest[: following.start()] if following else rest).strip()


def assessment_band(assessment: str) -> tuple[int, str]:
    """
    Map qualitative certainty language to a numeric band.

    Returns ``(band, matched_term)``. The weakest qualifier present wins.
    """

    text = (assessment or "").lower()

    if not text:
        return BAND_UNQUALIFIED, "no assessment section"

    for band, terms in _BANDS:
        for term in terms:
            if term in text:
                return band, term

    return BAND_UNQUALIFIED, "no certainty language"


def coverage_cap(unavailable_sources: int, total_sources: int) -> int | None:
    """
    Ceiling imposed by incomplete evidence coverage, or ``None``.

    A check that was never performed cannot be reported with the same
    confidence as one that was, regardless of how the model phrased it.
    """

    if not total_sources or not unavailable_sources:
        return None

    if unavailable_sources >= total_sources:
        return 30

    return 70


def calibrate(
    *,
    answer: str,
    cited_references: list[dict],
    insufficient: bool = False,
    unavailable_sources: int = 0,
    total_sources: int = 0,
    prior: int | None = None,
) -> tuple[int, str]:
    """
    Derive a calibrated confidence value and a one-line rationale.

    Parameters
    ----------
    answer : str
        The parsed answer text, including its ASSESSMENT section.

    cited_references : list[dict]
        Only the references the model actually cited — retrieved-but-uncited
        evidence says nothing about how well the finding is supported.

    insufficient : bool
        Whether the answer declared the evidence insufficient.

    unavailable_sources, total_sources : int
        Mapped-source coverage for a routed question. Zero/zero when the
        question was not routed.

    prior : int | None
        An externally computed confidence. Used only as an upper bound, so a
        future classifier that emits real scores can lower this result but
        never inflate it.
    """

    assessment = extract_assessment(answer)
    confidence, term = assessment_band(assessment)
    reasons = [f"assessment={term}({confidence})"]

    # Bounded adjustment from the evidence actually cited. Applied before the
    # ceilings below, never after: a bonus that outranks a cap is not a cap.
    if cited_references:
        risks = [
            (reference.get("risk_level") or "").lower()
            for reference in cited_references
        ]

        if "high" in risks:
            confidence += 10
            reasons.append("cited high-risk evidence(+10)")
        elif risks and all(
            risk in ("insufficient-evidence", "unknown", "") for risk in risks
        ):
            confidence -= 10
            reasons.append("cited evidence carries no risk signal(-10)")

    ceilings: list[tuple[int, str]] = [(CEILING, "ceiling")]

    # An uncited answer is an unsupported answer, whatever it asserts.
    if not cited_references:
        ceilings.append((25, "no citations"))

    if insufficient:
        ceilings.append((BAND_NONE, "insufficient"))

    cap = coverage_cap(unavailable_sources, total_sources)

    if cap is not None:
        ceilings.append(
            (cap, f"{unavailable_sources}/{total_sources} sources unavailable")
        )

    if prior is not None:
        ceilings.append((prior, "prior"))

    for limit, label in ceilings:
        if confidence > limit:
            confidence = limit
            reasons.append(f"{label}(<={limit})")

    confidence = max(0, min(CEILING, confidence))

    rationale = "; ".join(reasons)

    logger.info(
        "[CHAT] calibrated confidence %d — %s",
        confidence,
        rationale,
    )

    return confidence, rationale


__all__ = [
    "BAND_MODERATE",
    "BAND_NONE",
    "BAND_STRONG",
    "BAND_UNQUALIFIED",
    "BAND_WEAK",
    "CEILING",
    "assessment_band",
    "calibrate",
    "coverage_cap",
    "extract_assessment",
]
