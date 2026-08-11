"""
Deterministic risk scoring for the evidence classifier.

Scoring separates two concepts:

* ``confidence`` (extraction trust) - stored unchanged on the model.
* ``severity`` (forensic risk) - derived purely from matched indicators and
  cross-plugin corroboration, never from the confidence score.

A record never reaches HIGH from a single source unless it is corroborated
by other plugin families. Strong indicators (e.g. a remote endpoint in a
command line, or a non-loopback connection) raise a record to MEDIUM on
their own, but HIGH always requires corroboration.
"""

from __future__ import annotations

# ==============================================================================
# Thresholds (single source of truth, centralized for explainability)
# ==============================================================================

LOW_MEDIUM_SCORE = 3
MEDIUM_HIGH_SCORE = 6

CORROBORATION_BOOST = 2
ESCALATION_BOOST = 4

MIN_CORROBORATING_FAMILIES = 2
MIN_CORROBORATING_FAMILIES_MALFIND = 1

# Rule set version stamped on persisted classifications. Bump whenever the
# indicator tables or scoring thresholds change so historical records keep
# their original, explainable classification.
RULE_VERSION = "1.0"

# Severity states
LOW = "low"
MEDIUM = "medium"
HIGH = "high"
UNKNOWN = "unknown"
INSUFFICIENT_EVIDENCE = "insufficient-evidence"

VALID_SEVERITIES = (LOW, MEDIUM, HIGH, UNKNOWN, INSUFFICIENT_EVIDENCE)


def min_corroborating_families(artifact_type: str) -> int:
    """
    Return the number of corroborating families required for ``artifact_type``.

    ``windows.malfind`` is inherently high-signal (it exists specifically to
    detect injected memory), so a single corroborating family is sufficient
    there - the one explicit exception to the general corroboration rule.
    """

    if artifact_type == "malfind":
        return MIN_CORROBORATING_FAMILIES_MALFIND

    return MIN_CORROBORATING_FAMILIES


def evaluate(
    base_score: int,
    has_strong: bool,
    corroborated: bool,
) -> tuple[str, int]:
    """
    Map indicator score + corroboration onto a severity level.

    Returns ``(severity, final_score)``. Pure and deterministic.
    """

    if has_strong and corroborated:
        boost = ESCALATION_BOOST
    elif corroborated:
        boost = CORROBORATION_BOOST
    else:
        boost = 0

    final_score = base_score + boost

    if final_score >= MEDIUM_HIGH_SCORE and has_strong and corroborated:
        return HIGH, final_score

    if has_strong or final_score >= LOW_MEDIUM_SCORE:
        return MEDIUM, final_score

    return LOW, final_score
