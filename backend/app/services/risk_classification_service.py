"""
Risk classification persistence service.

Runs the EvidenceClassifier over every evidence record of an investigation
with the full investigation as the correlation corpus, and persists the
resulting classification on each record. Persisting the classification is
what lets the severity filter and pagination operate on the classifier's
actual risk level instead of the old confidence-score heuristic.

Existing records that already have a ``risk_level`` are left untouched.
"""

from __future__ import annotations

import json

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.repositories import PluginResultRepository
from app.services.evidence_classifier import evidence_classifier
from app.services.evidence_classifier.scorer import RULE_VERSION

logger = get_logger(__name__)


def classify_investigation_evidence(
    session: Session,
    investigation_id: str,
) -> int:
    """
    Classify and persist risk levels for an investigation's evidence.

    Returns the number of records updated.
    """

    repository = PluginResultRepository(session)

    records = repository.get_by_investigation(investigation_id)

    corpus = [
        {
            "id": record.id,
            "plugin": record.artifact_name,
            "artifact_type": record.artifact_type,
            "artifact_value": record.artifact_value,
        }
        for record in records
    ]

    updated = 0

    for record in records:

        if record.risk_level is not None:
            continue

        classification = evidence_classifier.classify(
            plugin=record.artifact_name,
            artifact_type=record.artifact_type,
            artifact_value=record.artifact_value,
            corpus=corpus,
            evidence_id=record.id,
        )

        record.risk_level = classification.severity
        record.risk_reasons = json.dumps(classification.reasons)
        record.risk_indicators = json.dumps(classification.indicators)
        record.rule_version = RULE_VERSION

        repository.update(record)

        updated += 1

    session.commit()

    logger.info(
        "Classified %d evidence records for investigation '%s'.",
        updated,
        investigation_id,
    )

    return updated
