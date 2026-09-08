"""
Memory-region qualification tests for malfind evidence.

The regression these guard: the classifier's malfind rule matches
unconditionally, so all 8,912 D2F9 malfind rows are stored as high severity.
8,856 of them describe mapped memory in signed Dell, Intel and Microsoft
software -- what a JIT compiler produces. Told this plainly in the prompt
preamble, the model still reported LicenseServer (PID 5572), a mapped region,
as "potential malicious code injection". The qualification therefore travels
with the row, and the ceiling is enforced in code.
"""

from __future__ import annotations

import pytest

from app.services.forensic_evidence_retrieval_service import (
    build_evidence_document,
)
from app.services.memory_region_context import (
    MAPPED,
    MAPPED_MARKER,
    MAPPED_ONLY_CEILING,
    PRIVATE,
    PRIVATE_MARKER,
    annotate_region,
    malfind_ceiling,
    region_kind,
)

MAPPED_ROW = {
    "pid": 5572,
    "process": "LicenseServer.",
    "protection": "PAGE_EXECUTE_READWRITE",
    "privatememory": 0,
}

PRIVATE_ROW = {
    "pid": 5864,
    "process": "MsMpEng.exe",
    "protection": "PAGE_EXECUTE_READWRITE",
    "privatememory": 1,
}


# ------------------------------------------------------------------
# Classification
# ------------------------------------------------------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        (0, MAPPED), ("0", MAPPED), ("false", MAPPED),
        (1, PRIVATE), ("1", PRIVATE), ("true", PRIVATE),
    ],
)
def test_private_memory_flag_determines_region_kind(value, expected):
    assert region_kind({"privatememory": value}) == expected


def test_row_without_the_field_is_not_classified():
    """An unqualifiable row must not be given a qualification it has not earned."""
    assert region_kind({"pid": 1}) is None
    assert region_kind({}) is None
    assert region_kind(None) is None


def test_unrecognised_value_is_not_classified():
    assert region_kind({"privatememory": "maybe"}) is None


# ------------------------------------------------------------------
# Annotation
# ------------------------------------------------------------------

def test_mapped_region_is_annotated_against_calling_it_injection():
    lines = "\n".join(annotate_region("malfind", MAPPED_ROW))
    assert MAPPED_MARKER in lines
    assert "just-in-time compiler" in lines
    assert "Do NOT describe this region as injected" in lines
    # The stored label is explained rather than contradicted.
    assert "assigned to every malfind row by rule" in lines


def test_private_region_is_reported_as_a_lead_needing_corroboration():
    lines = "\n".join(annotate_region("malfind", PRIVATE_ROW))
    assert PRIVATE_MARKER in lines
    assert "worth examining" in lines
    assert "corroboration is still required" in lines


def test_other_artifact_types_are_untouched():
    assert annotate_region("pslist", {"privatememory": 0}) == []
    assert annotate_region("netscan", MAPPED_ROW) == []


def test_malfind_row_without_the_field_gets_no_annotation():
    assert annotate_region("malfind", {"pid": 5572}) == []


# ------------------------------------------------------------------
# Rendering into the evidence block
# ------------------------------------------------------------------

def _document(attributes: dict) -> str:
    import json

    return build_evidence_document(
        "windows.malfind",
        "malfind",
        json.dumps(attributes),
        risk_level="high",
    )


def test_annotation_reaches_the_rendered_evidence_block():
    """
    The annotation must travel with the cited row. Stated only in a preamble
    several blocks away, it lost to the row's own high risk_level.
    """
    document = _document(MAPPED_ROW)
    assert "risk_level: high" in document
    assert MAPPED_MARKER in document
    assert "Do NOT describe this region as injected" in document


def test_private_row_renders_its_own_marker():
    assert PRIVATE_MARKER in _document(PRIVATE_ROW)


# ------------------------------------------------------------------
# Enforced ceiling
# ------------------------------------------------------------------

def _reference(attributes: dict) -> dict:
    return {"document": _document(attributes)}


def test_answer_citing_only_mapped_regions_is_capped():
    assert (
        malfind_ceiling([_reference(MAPPED_ROW), _reference(MAPPED_ROW)])
        == MAPPED_ONLY_CEILING
    )


def test_one_cited_private_region_lifts_the_cap():
    """The answer then rests on something that genuinely warrants attention."""
    assert (
        malfind_ceiling([_reference(MAPPED_ROW), _reference(PRIVATE_ROW)])
        is None
    )


def test_no_cap_when_no_malfind_row_was_cited():
    assert malfind_ceiling([{"document": "plugin: windows.pslist"}]) is None
    assert malfind_ceiling([]) is None
    assert malfind_ceiling(None) is None
