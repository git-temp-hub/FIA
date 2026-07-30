"""
Evidence Normalizer for the AI Memory Forensic Investigation Assistant.

This module converts plugin-specific Volatility output into a
standardized forensic evidence format.

Author:
    FIA Development Team
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)


# ==============================================================================
# Normalized Evidence
# ==============================================================================


@dataclass(slots=True)
class EvidenceRecord:
    """
    Represents one normalized forensic evidence record.
    """

    plugin: str

    artifact_type: str

    attributes: dict[str, Any]


# ==============================================================================
# Evidence Normalizer
# ==============================================================================


class EvidenceNormalizer:
    """
    Converts plugin-specific data into normalized evidence.
    """

    def __init__(self) -> None:
        logger.info(
            "Evidence Normalizer initialized."
        )

    # --------------------------------------------------------------------------
    # Generic Normalization
    # --------------------------------------------------------------------------

    def normalize_record(
        self,
        plugin_name: str,
        row: dict[str, Any],
    ) -> EvidenceRecord:
        """
        Normalize a single Volatility plugin row into a standard evidence record.
        """

        artifact_type = plugin_name.split(".")[-1]

        normalized_attributes = {
            key.lower(): value
            for key, value in row.items()
        }

        record = EvidenceRecord(
            plugin=plugin_name,
            artifact_type=artifact_type,
            attributes=normalized_attributes,
        )

        return record
    # --------------------------------------------------------------------------
    # Batch Normalization
    # --------------------------------------------------------------------------

    def normalize(
        self,
        plugin_name: str,
        rows: list[dict[str, Any]],
    ) -> list[EvidenceRecord]:
        """
        Normalize multiple Volatility rows into evidence records.
        """

        records: list[EvidenceRecord] = []

        for row in rows:
            records.append(
                self.normalize_record(
                    plugin_name=plugin_name,
                    row=row,
                )
            )

        logger.info(
            "Normalized %d evidence records from plugin '%s'.",
            len(records),
            plugin_name,
        )

        return records
# ==============================================================================
# Singleton Instance
# ==============================================================================

evidence_normalizer = EvidenceNormalizer()

# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "EvidenceRecord",
    "EvidenceNormalizer",
    "evidence_normalizer",
]