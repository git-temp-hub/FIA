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
from dataclasses import dataclass, field
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


# ==============================================================================
# Inverted-index correlation (O(candidates) instead of O(corpus) per record)
# ==============================================================================


@dataclass
class CorpusIndex:
    """
    Precomputed correlation index over an investigation corpus.

    ``entity_to_family_positions`` maps a canonical entity key to a dict of
    ``artifact_type -> [positions in ``entries``]`` so that correlating one
    record only touches records from *other* artifact families that actually
    share one of its entities - never the whole corpus.
    """

    entries: list[CorpusEntry]

    entity_to_family_positions: dict[
        tuple[Any, ...], dict[str, list[int]]
    ] = field(default_factory=dict)

    def positions_for(
        self,
        entity: tuple[Any, ...],
        artifact_type: str,
    ) -> tuple[int, ...]:
        """Return the corpus positions in ``artifact_type`` sharing ``entity``."""

        families = self.entity_to_family_positions.get(entity)

        if not families:
            return ()

        return tuple(families.get(artifact_type, ()))

    def families_for(
        self,
        entity: tuple[Any, ...],
    ) -> dict[str, list[int]]:
        """Return ``{artifact_type: [positions]}`` for a canonical entity."""

        return self.entity_to_family_positions.get(entity, {})


def build_corpus_index(entries: list[CorpusEntry]) -> CorpusIndex:
    """
    Build the inverted entity index for a corpus.

    Each canonical entity is mapped to the positions of every record that
    carries it, grouped by artifact type. ``build_corpus``/``build_entry``
    are still called exactly once per corpus, so the JSON parsing and entity
    extraction cost is O(corpus) total instead of O(corpus) per record.
    """

    entity_to_family_positions: dict[
        tuple[Any, ...], dict[str, list[int]]
    ] = {}

    for position, entry in enumerate(entries):

        family = entry.artifact_type

        for entity in entry.entities:

            families = entity_to_family_positions.setdefault(entity, {})

            families.setdefault(family, []).append(position)

    return CorpusIndex(
        entries=entries,
        entity_to_family_positions=entity_to_family_positions,
    )


def correlate_indexed(
    entry: CorpusEntry,
    index: CorpusIndex,
    min_families: int = 2,
) -> CorrelationResult:
    """
    Correlate ``entry`` against a prebuilt ``CorpusIndex``.

    Semantics are identical to :func:`correlate`: corroboration requires at
    least ``min_families`` distinct other artifact types sharing at least one
    canonical entity with ``entry``, with the same self-exclusion and
    same-family exclusion rules. Only records from *other* families that share
    an entity are ever visited, so large same-family groups (e.g. thousands of
    ``dlllist`` rows for one PID) are not re-scanned for every record.
    """

    if entry is None or not entry.entities:
        return CorrelationResult(
            corroborated=False,
            families=[],
            evidence=[],
        )

    family_positions: dict[str, list[int]] = {}
    seen: set[int] = set()

    for entity in entry.entities:

        for family, positions in index.families_for(entity).items():

            if family == entry.artifact_type:
                continue

            for position in positions:

                if position in seen:
                    continue

                other = index.entries[position]

                if other.evidence_id == entry.evidence_id:
                    continue

                seen.add(position)
                family_positions.setdefault(family, []).append(position)

    families = sorted(family_positions.keys())

    corroborating: list[tuple[str, int]] = []

    for family in families:
        for position in sorted(family_positions[family]):
            other = index.entries[position]
            corroborating.append((other.plugin, other.evidence_id))

    corroborated = len(families) >= min_families

    return CorrelationResult(
        corroborated=corroborated,
        families=families,
        evidence=corroborating,
    )
