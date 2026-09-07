"""
Confidence calibration tests.

The regression these guard: every persisted ``confidence_score`` is the
constant 100, so the previous evidence-score path returned 100 for every
answer — including answers whose own ASSESSMENT read "certainty is moderate"
and answers resting on a plugin that never ran.
"""

from __future__ import annotations

import pytest

from app.llm.confidence import (
    BAND_MODERATE,
    BAND_STRONG,
    BAND_WEAK,
    CEILING,
    assessment_band,
    calibrate,
    coverage_cap,
    extract_assessment,
)

HIGH = [{"risk_level": "high"}]
LOW = [{"risk_level": "low"}]
NOSIGNAL = [{"risk_level": "insufficient-evidence"}]


def _answer(assessment: str, gaps: str = "None.") -> str:
    return (
        "FINDING\nSomething.\n\n"
        "EVIDENCE\n- A fact [1].\n\n"
        f"ASSESSMENT\n{assessment}\n\n"
        f"GAPS\n{gaps}\n"
    )


# ------------------------------------------------------------------
# Section extraction
# ------------------------------------------------------------------

def test_extracts_assessment_section():
    text = _answer("Certainty is moderate.")
    assert extract_assessment(text) == "Certainty is moderate."


def test_extracts_assessment_with_markdown_decoration():
    text = "**FINDING**\nx\n\n**ASSESSMENT**\nSupport is strong.\n\n**GAPS**\nNone."
    assert extract_assessment(text) == "Support is strong."


def test_missing_assessment_returns_empty():
    assert extract_assessment("FINDING\nx\n") == ""


# ------------------------------------------------------------------
# Band mapping
# ------------------------------------------------------------------

@pytest.mark.parametrize(
    "assessment,expected",
    [
        ("The evidence strongly supports this.", BAND_STRONG),
        ("Certainty is moderate.", BAND_MODERATE),
        ("Support is weak and inconclusive.", BAND_WEAK),
        ("This cannot be determined from what was supplied.", 15),
    ],
)
def test_band_follows_certainty_language(assessment, expected):
    band, _ = assessment_band(assessment)
    assert band == expected


def test_weakest_qualifier_wins():
    """
    The real Q14 answer read "strongly supports ... Certainty is moderate".
    The hedge is the operative half; grading it as strong is the bug.
    """
    band, _ = assessment_band(
        "The evidence strongly supports the conclusion. "
        "Certainty is moderate due to the absence of explicit risk markers."
    )
    assert band == BAND_MODERATE


# ------------------------------------------------------------------
# Calibration
# ------------------------------------------------------------------

def test_never_returns_one_hundred_even_at_full_strength():
    value, _ = calibrate(
        answer=_answer("Directly and conclusively supported, unambiguous."),
        cited_references=HIGH * 3,
        prior=100,
    )
    assert value <= CEILING < 100


def test_moderate_assessment_does_not_report_high_confidence():
    value, _ = calibrate(
        answer=_answer("Certainty is moderate."),
        cited_references=LOW,
        prior=100,
    )
    assert value == BAND_MODERATE


def test_uncited_answer_is_capped():
    value, _ = calibrate(
        answer=_answer("The evidence strongly and clearly supports this."),
        cited_references=[],
        prior=100,
    )
    assert value <= 25


def test_insufficient_answer_is_capped_low():
    value, _ = calibrate(
        answer=_answer("Support is strong."),
        cited_references=HIGH,
        insufficient=True,
        prior=100,
    )
    assert value <= 15


def test_unavailable_source_ceilings_confidence():
    """Q2's memmap never ran; a strong assessment must not reach the top band."""
    value, _ = calibrate(
        answer=_answer("The evidence strongly and clearly supports this."),
        cited_references=HIGH,
        unavailable_sources=1,
        total_sources=5,
        prior=100,
    )
    assert value == 70


def test_all_sources_unavailable_ceilings_harder():
    value, _ = calibrate(
        answer=_answer("Support is strong."),
        cited_references=HIGH,
        unavailable_sources=3,
        total_sources=3,
        prior=100,
    )
    assert value == 30


def test_prior_can_only_lower_never_raise():
    value, _ = calibrate(
        answer=_answer("Support is strong and unambiguous."),
        cited_references=HIGH,
        prior=40,
    )
    assert value == 40


def test_evidence_without_risk_signal_reduces_confidence():
    strong = _answer("Certainty is moderate.")
    with_signal, _ = calibrate(
        answer=strong, cited_references=LOW, prior=100
    )
    without_signal, _ = calibrate(
        answer=strong, cited_references=NOSIGNAL, prior=100
    )
    assert without_signal < with_signal


def test_confidence_varies_across_differing_assessments():
    """The headline regression: distinct answers must not all score alike."""
    values = {
        calibrate(
            answer=_answer(text), cited_references=LOW, prior=100
        )[0]
        for text in (
            "Support is strong, direct and unambiguous.",
            "Certainty is moderate.",
            "Support is weak and inconclusive.",
            "This cannot be determined.",
        )
    }
    assert len(values) == 4


# ------------------------------------------------------------------
# Coverage cap
# ------------------------------------------------------------------

def test_coverage_cap_absent_when_everything_searched():
    assert coverage_cap(0, 4) is None
    assert coverage_cap(0, 0) is None


def test_coverage_cap_tightens_as_coverage_worsens():
    assert coverage_cap(1, 4) == 70
    assert coverage_cap(4, 4) == 30
