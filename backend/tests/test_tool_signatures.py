"""
Known-tool signature matching tests.

Each test here corresponds to a false positive or silent miss found while
building the catalogue against the real D2F9 corpus.
"""

from __future__ import annotations

import re

import pytest

from app.services.tool_signatures import (
    CATALOGUE,
    EXECUTED,
    NETWORK,
    ON_DISK,
    ToolMatch,
    ToolSignature,
    process_name_matches,
    format_tool_matches,
)


# ------------------------------------------------------------------
# Process-name comparison
# ------------------------------------------------------------------

def test_exact_process_name_matches():
    assert process_name_matches("anydesk.exe", "anydesk.exe")
    assert process_name_matches("AnyDesk.EXE", "anydesk.exe")


def test_truncated_process_name_still_matches():
    """
    The EPROCESS ImageFileName field is fixed-width, so Volatility reports
    "CodeMeterCC.exe" as "CodeMeterCC.ex". Comparing exactly against a longer
    catalogue entry silently never fires.
    """
    assert process_name_matches("advanced_ip_sc", "advanced_ip_scanner.exe")
    assert process_name_matches("screenconnect.", "screenconnect.clientservice.exe")


def test_short_prefix_does_not_match():
    """Truncation only excuses a name long enough to have filled the field."""
    assert not process_name_matches("ad", "advanced_ip_scanner.exe")
    assert not process_name_matches("sc.exe", "screenconnect.clientservice.exe")


def test_unrelated_names_do_not_match():
    assert not process_name_matches("svchost.exe", "anydesk.exe")
    assert not process_name_matches("", "anydesk.exe")


def test_legitimate_oem_software_is_not_matched():
    """
    A trial catalogue containing the substring "assist" matched 312 rows on
    D2F9, all of them Dell SupportAssist. No catalogue entry may match it.
    """
    for observed in ("SupportAssistA", "DellSupportAss", "SupportAssistAgent.exe"):
        for tool in CATALOGUE:
            assert not any(
                process_name_matches(observed, name) for name in tool.processes
            ), f"{tool.name} matched {observed}"


# ------------------------------------------------------------------
# Catalogue hygiene
# ------------------------------------------------------------------

def test_every_entry_has_at_least_one_matchable_signal():
    for tool in CATALOGUE:
        assert (
            tool.processes or tool.paths or tool.cmdline_tokens or tool.cmdline_regex
        ), tool.name


def test_builtin_tools_declare_no_disk_paths():
    """
    mstsc.exe sits in System32 on every Windows install. Matching built-ins
    on disk reports the operating system as a finding.
    """
    for tool in CATALOGUE:
        if tool.builtin:
            assert not tool.paths, tool.name


def test_path_fragments_are_anchored():
    """An unanchored fragment is a substring match by another name."""
    for tool in CATALOGUE:
        for fragment in tool.paths:
            assert fragment.startswith("\\"), f"{tool.name}: {fragment}"


def test_command_line_tokens_are_distinctive():
    """
    "\\\\" matched the local named pipe \\\\.\\pipe\\pm2_igs and reported
    PresentMonService as remote service control.
    """
    for tool in CATALOGUE:
        for token in tool.cmdline_tokens:
            assert len(token.strip("\\/")) >= 5, f"{tool.name}: {token!r}"


def test_every_regex_compiles():
    for tool in CATALOGUE:
        if tool.cmdline_regex:
            re.compile(tool.cmdline_regex)


# ------------------------------------------------------------------
# Remote service control
# ------------------------------------------------------------------

def _sc_regex() -> str:
    return next(
        tool for tool in CATALOGUE if tool.name == "Service control (remote)"
    ).cmdline_regex


@pytest.mark.parametrize(
    "args,expected",
    [
        (r"sc.exe \\FILESERVER create svc binPath= c:\x.exe", True),
        (r"sc \\10.10.101.5 start beacon", True),
        (r"sc.exe query", False),
        (r"sc.exe \\.\pipe\local", False),
        # The real D2F9 false positive.
        (
            r'"PresentMonService.exe" --control-pipe \\.\pipe\pm2_igs '
            r"--shm-name-prefix Global\pm2_igs",
            False,
        ),
    ],
)
def test_remote_service_control_ignores_local_named_pipes(args, expected):
    assert bool(re.search(_sc_regex(), args, re.IGNORECASE)) is expected


# ------------------------------------------------------------------
# Rendering
# ------------------------------------------------------------------

def _match(strength: str) -> ToolMatch:
    tool = ToolSignature("AnyDesk", "remote access", processes=("anydesk.exe",))
    return ToolMatch(tool, strength, [1], ["process anydesk.exe (PID 900)"])


def test_empty_scan_states_its_own_limits():
    block = format_tool_matches([])
    assert "no matches" in block
    assert "renamed binaries" in block


def test_rendered_match_carries_strength_and_corroboration_warning():
    block = format_tool_matches([_match(EXECUTED)])
    assert "AnyDesk" in block
    assert EXECUTED in block
    assert "leads, not conclusions" in block


@pytest.mark.parametrize("strength", [EXECUTED, ON_DISK, NETWORK])
def test_all_strengths_render(strength):
    assert strength in format_tool_matches([_match(strength)])
