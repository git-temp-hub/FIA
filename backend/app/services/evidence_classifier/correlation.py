"""
Cross-plugin correlation for the evidence classifier.

Correlation joins evidence within the same investigation on canonical
entities (PID, process name, file path, connection, registry key) and
counts how many *other* plugin families independently reference the same
entity. Independent agreement is the corroboration that lets a suspicious
artifact escalate from MEDIUM to HIGH.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.services.evidence_classifier.entities import extract_entities

# ==============================================================================
# Corpus Model
# ==============================================================================


@dataclass(frozen=True)
class CorpusEntry:
    """One record in the correlation corpus."""

    evidence_id: int | None
    plugin: str
    artifact_type: str
    entities: frozenset[tuple[Any, ...]]


def parse_attributes(artifact_value: str | None) -> dict[str, Any] | None:
    """
    Parse an ``artifact_value`` JSON blob into a lowercased attribute dict.

    Returns ``None`` when the value is empty or not valid JSON.
    """

    if artifact_value is None:
        return None

    text = artifact_value.strip()

    if not text:
        return None

    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return None

    if not isinstance(parsed, dict):
        return None

    return {str(key).lower(): value for key, value in parsed.items()}


def build_entry(
    evidence_id: int | None,
    plugin: str,
    artifact_type: str,
    artifact_value: str | None,
) -> CorpusEntry | None:
    """Build a CorpusEntry from raw record fields, or None when unparseable."""

    attributes = parse_attributes(artifact_value)

    if attributes is None or not attributes:
        return None

    entities = frozenset(
        extract_entities(
            artifact_type=artifact_type,
            attributes=attributes,
        )
    )

    return CorpusEntry(
        evidence_id=evidence_id,
        plugin=plugin,
        artifact_type=artifact_type,
        entities=entities,
    )


def build_corpus(records: list[dict[str, Any]]) -> list[CorpusEntry]:
    """Build a correlation corpus from a list of raw record dicts."""

    entries: list[CorpusEntry] = []

    for record in records:
        entry = build_entry(
            evidence_id=record.get("id"),
            plugin=str(record.get("plugin", "")),
            artifact_type=str(record.get("artifact_type", "")),
            artifact_value=record.get("artifact_value"),
        )

        if entry is not None:
            entries.append(entry)

    return entries


# ==============================================================================
# Correlation Result
# ==============================================================================


@dataclass(frozen=True)
class CorrelationResult:
    """Outcome of correlating one record against a corpus."""

    corroborated: bool
    families: list[str]
    evidence: list[tuple[str, int]]


def correlate(
    entry: CorpusEntry,
    corpus: list[CorpusEntry],
    min_families: int = 2,
) -> CorrelationResult:
    """
    Correlate ``entry`` against ``corpus``.

    A record is corroborated when at least ``min_families`` distinct other
    artifact types share at least one canonical entity with it.
    """

    if entry is None or not entry.entities:
        return CorrelationResult(
            corroborated=False,
            families=[],
            evidence=[],
        )

    family_evidence: dict[str, list[tuple[str, int]]] = {}

    for other in corpus:
        if other.evidence_id == entry.evidence_id:
            continue

        if other.artifact_type == entry.artifact_type:
            continue

        if not entry.entities.isdisjoint(other.entities):
            family_evidence.setdefault(other.artifact_type, []).append(
                (other.plugin, other.evidence_id)
            )

    families = sorted(family_evidence.keys())

    corroborating: list[tuple[str, int]] = []

    for family in families:
        corroborating.extend(family_evidence[family])

    corroborated = len(families) >= min_families

    return CorrelationResult(
        corroborated=corroborated,
        families=families,
        evidence=corroborating,
    )
