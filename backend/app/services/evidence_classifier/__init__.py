"""
Evidence Classifier - deterministic, explainable forensic risk scoring.

Phase 0 MVP: severity is derived from artifact/plugin-specific indicators and
cross-plugin correlation, independent of the stored confidence score.
"""

from app.services.evidence_classifier.classifier import Classification
from app.services.evidence_classifier.classifier import EvidenceClassifier
from app.services.evidence_classifier.classifier import evidence_classifier
from app.services.evidence_classifier.correlation import (
    CorpusEntry,
    CorpusIndex,
    build_corpus,
    build_corpus_index,
    correlate_indexed,
    parse_attributes,
)
from app.services.evidence_classifier.scorer import (
    HIGH,
    INSUFFICIENT_EVIDENCE,
    LOW,
    MEDIUM,
    UNKNOWN,
    VALID_SEVERITIES,
)

__all__ = [
    "Classification",
    "EvidenceClassifier",
    "evidence_classifier",
    "CorpusEntry",
    "CorpusIndex",
    "build_corpus",
    "build_corpus_index",
    "correlate_indexed",
    "parse_attributes",
    "LOW",
    "MEDIUM",
    "HIGH",
    "UNKNOWN",
    "INSUFFICIENT_EVIDENCE",
    "VALID_SEVERITIES",
]
