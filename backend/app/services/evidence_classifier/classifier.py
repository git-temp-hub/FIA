"""
Evidence Classifier facade for the AI Memory Forensic Investigation Assistant.

Deterministic, explainable forensic risk classification. Severity is derived
from artifact/plugin-specific indicators plus cross-plugin corroboration and
is fully independent of the stored ``confidence_score`` (extraction trust).

States
------
* ``low``
* ``medium``
* ``high``
* ``unknown`` (no parseable semantic data)
* ``insufficient-evidence`` (artifact type with no risk indicators)

Every MEDIUM/HIGH classification includes a list of matched indicator codes
and human-readable reasons citing the exact evidence.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from dataclasses import field
from typing import Any

from app.core.logging import get_logger
from app.services.evidence_classifier.correlation import (
    CorpusIndex,
    CorrelationResult,
    build_corpus,
    build_corpus_index,
    build_entry,
    correlate_indexed,
    parse_attributes,
)
from app.services.evidence_classifier.indicators import indicators_for
from app.services.evidence_classifier.indicators import is_supported
from app.services.evidence_classifier.scorer import HIGH
from app.services.evidence_classifier.scorer import INSUFFICIENT_EVIDENCE
from app.services.evidence_classifier.scorer import LOW
from app.services.evidence_classifier.scorer import MEDIUM
from app.services.evidence_classifier.scorer import UNKNOWN
from app.services.evidence_classifier.scorer import evaluate
from app.services.evidence_classifier.scorer import min_corroborating_families

logger = get_logger(__name__)


# ==============================================================================
# Classification Model
# ==============================================================================


@dataclass(slots=True)
class Classification:
    """Result of classifying a single evidence record."""

    severity: str

    reasons: list[str] = field(default_factory=list)

    indicators: list[str] = field(default_factory=list)

    score: int = 0

    corroborated: bool = False


def _format_reason(
    template: str,
    attributes: dict[str, Any],
) -> str:
    """Format an indicator reason template without raising on missing keys."""

    safe = defaultdict(str, attributes)

    try:
        return template.format_map(safe)
    except (KeyError, ValueError):
        return template


# ==============================================================================
# Classifier
# ==============================================================================


class EvidenceClassifier:
    """Deterministic, rule-based evidence risk classifier."""

    def classify(
        self,
        plugin: str,
        artifact_type: str,
        artifact_value: str | None,
        corpus: list[dict[str, Any]] | CorpusIndex | None = None,
        evidence_id: int | None = None,
    ) -> Classification:
        """
        Classify a single evidence record.

        Parameters
        ----------
        plugin : the Volatility plugin name (e.g. ``windows.pslist``).
        artifact_type : normalized artifact type (e.g. ``pslist``).
        artifact_value : JSON blob of normalized attributes.
        corpus : optional raw record list ``[{"id", "plugin",
            "artifact_type", "artifact_value"}]`` OR a prebuilt
            :class:`~app.services.evidence_classifier.correlation.CorpusIndex`
            used for cross-plugin correlation within the investigation. A
            prebuilt index is recomputed only once per investigation instead
            of once per record.
        evidence_id : the id of the record being classified (excludes itself
            from correlation).

        Returns
        -------
        Classification with a severity state, indicator codes, and reasons.
        """

        attributes = parse_attributes(artifact_value)

        if attributes is None or not attributes:
            return Classification(
                severity=UNKNOWN,
                reasons=[
                    "evidence attributes could not be parsed - "
                    "no semantic data available to classify"
                ],
            )

        if not is_supported(artifact_type):
            return Classification(
                severity=INSUFFICIENT_EVIDENCE,
                reasons=[
                    f"artifact type '{artifact_type}' has no risk indicators - "
                    "insufficient evidence to classify"
                ],
            )

        matched = [
            indicator
            for indicator in indicators_for(artifact_type)
            if indicator.match(attributes)
        ]

        base_score = sum(indicator.weight for indicator in matched)
        has_strong = any(indicator.strong for indicator in matched)

        corroborated = False
        correlation = CorrelationResult(
            corroborated=False,
            families=[],
            evidence=[],
        )

        entry = build_entry(
            evidence_id=evidence_id,
            plugin=plugin,
            artifact_type=artifact_type,
            artifact_value=artifact_value,
        )

        if corpus and entry is not None:

            if isinstance(corpus, CorpusIndex):
                index = corpus
            else:
                entries = build_corpus(corpus)
                index = build_corpus_index(entries)

            correlation = correlate_indexed(
                entry=entry,
                index=index,
                min_families=min_corroborating_families(artifact_type),
            )
            corroborated = correlation.corroborated

        severity, score = evaluate(
            base_score=base_score,
            has_strong=has_strong,
            corroborated=corroborated,
        )

        reasons: list[str] = []

        for indicator in matched:
            reasons.append(
                _format_reason(indicator.reason_template, attributes)
            )

        if corroborated and correlation.evidence and severity in (MEDIUM, HIGH):
            references = ", ".join(
                f"{plugin_name}(#{evidence_ref})"
                for plugin_name, evidence_ref in correlation.evidence
            )
            reasons.append(
                f"corroborated by independent plugin evidence: {references}"
            )

        indicators = [indicator.code for indicator in matched]

        return Classification(
            severity=severity,
            reasons=reasons,
            indicators=indicators,
            score=score,
            corroborated=corroborated,
        )


# ==============================================================================
# Singleton
# ==============================================================================

evidence_classifier = EvidenceClassifier()


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "Classification",
    "EvidenceClassifier",
    "evidence_classifier",
    "build_corpus",
    "parse_attributes",
    "LOW",
    "UNKNOWN",
    "INSUFFICIENT_EVIDENCE",
]