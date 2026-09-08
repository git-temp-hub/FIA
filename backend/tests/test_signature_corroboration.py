"""
Signature-corroboration tests.

The regression these guard: on D2F9, 131 of 134 YARA matches sit inside
MsMpEng.exe — Microsoft Defender's antimalware service, which holds malware
signatures in memory. Asked to triage them, the model reported "the presence
of XMRig cryptocurrency mining malware" in three consecutive runs at
temperature 0.0, with GAPS: None. One earlier run happened to spot the false
positive, which made a systematic failure look like sampling variance.

The check therefore runs in code, and its result is stated to the reader
whatever the model concludes.
"""

from __future__ import annotations

import pytest

from app.services.signature_corroboration import (
    PARTIAL_CEILING,
    UNCORROBORATED_CEILING,
    RuleCorroboration,
    SignatureAssessment,
    confidence_ceiling,
    corroboration_notice,
    format_corroboration,
    is_low_information,
    security_product_for,
)


# ------------------------------------------------------------------
# Security-product identification
# ------------------------------------------------------------------

def test_defender_is_recognised():
    assert security_product_for("MsMpEng.exe") == (
        "Microsoft Defender (antimalware service)"
    )


def test_recognition_is_case_insensitive():
    assert security_product_for("msmpeng.exe") is not None


def test_truncated_security_process_is_recognised():
    """
    Volatility truncates the fixed-width name field, so the Defender core
    service arrives as "MpDefenderCore". An exact comparison misses it.
    """
    assert security_product_for("MpDefenderCore") is not None
    assert security_product_for("SecurityHealth") is not None


def test_ordinary_processes_are_not_security_products():
    for name in ("svchost.exe", "explorer.exe", "msedgewebview2", "chrome.exe"):
        assert security_product_for(name) is None


def test_empty_name_is_not_a_security_product():
    assert security_product_for("") is None


# ------------------------------------------------------------------
# Match quality
# ------------------------------------------------------------------

def test_null_padding_is_content_free():
    """One real D2F9 match was eleven consecutive null bytes."""
    assert is_low_information("00 00 00 00 00 00 00 00 00 00 00")


def test_repeated_byte_run_is_content_free():
    assert is_low_information("ff ff ff ff ff ff ff ff")


def test_real_string_match_is_informative():
    # "stratum+tcp"
    assert not is_low_information("73 74 72 61 74 75 6d 2b 74 63 70")


def test_short_sequences_are_kept():
    """Too short to judge; discarding them would lose real matches."""
    assert not is_low_information("00 00")


def test_empty_value_is_content_free():
    assert is_low_information("")


# ------------------------------------------------------------------
# Corroboration state
# ------------------------------------------------------------------

def _rule(name, total, hosted=0, empty=0, corroborating=0):
    return RuleCorroboration(
        rule=name,
        total=total,
        in_security_product=hosted,
        low_information=empty,
        corroborating=corroborating,
        products={"Microsoft Defender (antimalware service)"} if hosted else set(),
        corroborating_processes={"evil.exe"} if corroborating else set(),
    )


def test_rule_seen_only_inside_defender_is_uncorroborated():
    assert _rule("Mimikatz_Memory_Rule_1", 4, hosted=4).uncorroborated


def test_rule_seen_elsewhere_is_corroborated():
    assert not _rule("XMRIG_Miner", 5, hosted=3, corroborating=2).uncorroborated


def test_content_free_matches_never_corroborate():
    """A rule firing on null padding has not been corroborated by it."""
    assert _rule("XMRIG_Miner", 5, hosted=4, empty=1).uncorroborated


# ------------------------------------------------------------------
# Enforced ceilings
# ------------------------------------------------------------------

def test_no_matches_imposes_no_ceiling():
    assert confidence_ceiling(SignatureAssessment()) is None


def test_all_uncorroborated_caps_hard():
    assessment = SignatureAssessment(
        rules=[_rule("Mimikatz_Memory_Rule_1", 4, hosted=4)],
        total_matches=4,
    )
    assert confidence_ceiling(assessment) == UNCORROBORATED_CEILING


def test_partial_corroboration_still_caps():
    """
    The real D2F9 shape: one rule has two weak matches outside Defender, so
    "all uncorroborated" is false — but the answer still names Cobalt Strike
    and Mimikatz, whose matches sit only in Defender's memory.
    """
    assessment = SignatureAssessment(
        rules=[
            _rule("XMRIG_Miner", 115, hosted=112, empty=1, corroborating=2),
            _rule("Mimikatz_Memory_Rule_1", 4, hosted=4),
        ],
        total_matches=119,
    )
    assert confidence_ceiling(assessment) == PARTIAL_CEILING


def test_fully_corroborated_imposes_no_ceiling():
    assessment = SignatureAssessment(
        rules=[_rule("XMRIG_Miner", 5, corroborating=5)],
        total_matches=5,
    )
    assert confidence_ceiling(assessment) is None


# ------------------------------------------------------------------
# Prompt block
# ------------------------------------------------------------------

def test_prompt_block_forbids_reporting_uncorroborated_malware():
    block = format_corroboration(
        SignatureAssessment(
            rules=[_rule("Mimikatz_Memory_Rule_1", 4, hosted=4)],
            total_matches=4,
        )
    )
    assert "REQUIRED" in block
    assert "must NOT report" in block
    assert "Mimikatz_Memory_Rule_1" in block
    assert "GAPS" in block


def test_prompt_block_accepts_corroborated_findings():
    block = format_corroboration(
        SignatureAssessment(
            rules=[_rule("XMRIG_Miner", 5, corroborating=5)],
            total_matches=5,
        )
    )
    assert "REQUIRED" not in block
    assert "corroborated" in block


def test_prompt_block_handles_no_matches():
    assert "No YARA matches" in format_corroboration(SignatureAssessment())


# ------------------------------------------------------------------
# Appended notice
# ------------------------------------------------------------------

def test_notice_is_emitted_for_uncorroborated_rules():
    notice = corroboration_notice(
        SignatureAssessment(
            rules=[_rule("Mimikatz_Memory_Rule_1", 4, hosted=4)],
            total_matches=4,
        )
    )
    assert "AUTOMATED CORROBORATION CHECK" in notice
    assert "not the model" in notice
    assert "Mimikatz_Memory_Rule_1" in notice
    assert "not evidence of infection" in notice


def test_notice_reports_the_overall_proportion():
    """The headline fact is how much of the whole set is AV-hosted."""
    notice = corroboration_notice(
        SignatureAssessment(
            rules=[
                _rule("XMRIG_Miner", 115, hosted=112, empty=1, corroborating=2),
                _rule("Mimikatz_Memory_Rule_1", 4, hosted=4),
            ],
            total_matches=119,
        )
    )
    assert "116 of 119" in notice


@pytest.mark.parametrize(
    "assessment",
    [
        SignatureAssessment(),
        SignatureAssessment(
            rules=[_rule("XMRIG_Miner", 5, corroborating=5)], total_matches=5
        ),
    ],
)
def test_no_notice_when_nothing_is_uncorroborated(assessment):
    assert corroboration_notice(assessment) == ""
