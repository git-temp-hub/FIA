"""
Evidence Classifier - deterministic, explainable forensic risk scoring.

Phase 0 MVP: severity is derived from artifact/plugin-specific indicators and
cross-plugin correlation, independent of the stored confidence score.
"""

from app.services.evidence_classifier.classifier import Classification
from app.services.evidence_classifier.classifier import EvidenceClassifier
from app.services.evidence_classifier.classifier import evidence_classifier
from app.services.evidence_classifier.correlation import build_corpus
from app.services.evidence_classifier.correlation import parse_attributes
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
    "build_corpus",
    "parse_attributes",
    "LOW",
    "MEDIUM",
    "HIGH",
    "UNKNOWN",
    "INSUFFICIENT_EVIDENCE",
    "VALID_SEVERITIES",
]
