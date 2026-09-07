"""
Question-routing and evidence-coverage tests.

The regression these guard: semantic search alone ranked a `handles` row above
the `pstree` row that answered the question, and an answer built from whatever
evidence happened to be retrieved reported "no code injection was found" with
full confidence on an investigation where `malfind` had timed out.
"""

from __future__ import annotations

import pytest

from app.llm.response_parser import ResponseParser
from app.services.question_routing import (
    AVAILABLE,
    RAN_EMPTY,
    ROUTES,
    UNAVAILABLE,
    SourceCoverage,
    format_coverage,
    match_route,
)


# ------------------------------------------------------------------
# Route matching
# ------------------------------------------------------------------

@pytest.mark.parametrize(
    "question,expected",
    [
        ("Identify suspicious and malicious processes", "Q1"),
        ("Is there evidence of code injection or process hollowing", "Q2"),
        ("Was PowerShell used to run an encoded command", "Q4"),
        ("Which network connections were established", "Q6"),
        ("Identify persistence mechanisms and autorun entries", "Q14"),
        ("What YARA signature matches were found", "Q18"),
        ("Any indications of Mimikatz or credential dumping", "Q11"),
    ],
)
def test_questions_route_to_expected_entry(question, expected):
    route = match_route(question)
    assert route is not None
    assert route.qid == expected


def test_longer_phrase_outranks_generic_keyword():
    """
    "process hollowing" must beat the bare "process" hit, or an injection
    question lands on the process-listing route and never reaches malfind.
    """
    route = match_route("Is there evidence of process hollowing")
    assert route is not None and route.qid == "Q2"


def test_unrelated_question_returns_none_for_semantic_fallback():
    assert match_route("what is the weather today") is None
    assert match_route("") is None


def test_browser_authentication_question_is_flagged_out_of_scope():
    """Q9 needs disk/browser forensics; it must not be answered from memory."""
    route = match_route("Was there M365 browser authentication activity")
    assert route is not None
    assert route.qid == "Q9"
    assert route.out_of_scope
    assert route.plugins == ()


def test_every_route_declares_plugins_or_a_reason_not_to():
    for route in ROUTES:
        assert route.plugins or route.out_of_scope or route.synthesis, route.qid


# ------------------------------------------------------------------
# Coverage rendering
# ------------------------------------------------------------------

def _route(qid="Q2"):
    return next(entry for entry in ROUTES if entry.qid == qid)


def test_unavailable_source_is_named_and_gaps_is_mandated():
    block = format_coverage(
        _route(),
        [
            SourceCoverage("windows.malfind", AVAILABLE, 8912, "8,912 records"),
            SourceCoverage("windows.memmap", UNAVAILABLE, 0, "attempted; timeout"),
        ],
    )
    assert "UNAVAILABLE" in block
    assert "windows.memmap" in block
    # The Q2 regression: GAPS read "None." while memmap had never run.
    assert "REQUIRED" in block and "GAPS" in block
    assert '"None."' in block


def test_ran_empty_source_supports_a_negative_finding():
    block = format_coverage(
        _route(),
        [SourceCoverage("windows.malfind", RAN_EMPTY, 0, "produced no records")],
    )
    assert "meaningful negative finding" in block
    assert "REQUIRED" not in block


def test_ran_empty_is_usable_but_unavailable_is_not():
    assert SourceCoverage("p", AVAILABLE, 1).usable
    assert SourceCoverage("p", RAN_EMPTY, 0).usable
    assert not SourceCoverage("p", UNAVAILABLE, 0).usable


# ------------------------------------------------------------------
# Citation parsing
# ------------------------------------------------------------------

@pytest.mark.parametrize(
    "text,expected",
    [
        ("single [3]", [3]),
        ("group [4,5]", [4, 5]),
        ("spaced group [4, 5]", [4, 5]),
        ("range [1-6]", [1, 2, 3, 4, 5, 6]),
        ("en dash [2\u20134]", [2, 3, 4]),
        ("em dash [2\u20144]", [2, 3, 4]),
        ("clamped to supplied evidence [4-99]", [4, 5, 6]),
        ("reversed range dropped, [5-2] and [1]", [1]),
        ("duplicates collapse [2][2][2]", [2]),
        ("out of range ignored [0] [99]", []),
        ("no citations at all", []),
    ],
)
def test_citation_forms_are_all_parsed(text, expected):
    """
    Models use every one of these forms interchangeably. Matching only "[digit]"
    dropped each group after the first, and a range citation reported zero
    citations for an answer that had cited six records.
    """
    parsed = ResponseParser().parse_answer(text, num_evidence=6)
    assert parsed["citations"] == expected


def test_confidence_line_is_stripped_from_the_answer_body():
    parsed = ResponseParser().parse_answer(
        "FINDING\nSomething [1].\n\nCONFIDENCE: 60",
        num_evidence=6,
    )
    assert "CONFIDENCE" not in parsed["answer"]
    assert parsed["citations"] == [1]
