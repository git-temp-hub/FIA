"""
Corpus overview and timeline tests for the integrated assessment (Q20).

The regression these guard: answered through ordinary retrieval, Q20 sampled
six pslist rows out of 326,506 -- System, Registry, smss.exe, csrss.exe --
never reached malfind, netscan or the YARA results, and concluded "no
malicious activity is detected" at confidence 75.
"""

from __future__ import annotations

from app.services.incident_synthesis import (
    CorpusOverview,
    MalfindBreakdown,
    PluginSummary,
    TimelineEvent,
    _deduplicate,
    _parse_timestamp,
    format_overview,
    format_timeline,
)


# ------------------------------------------------------------------
# Timestamps
# ------------------------------------------------------------------

def test_iso_timestamp_is_kept():
    assert _parse_timestamp("2026-08-28T05:23:07+00:00").startswith("2026-08-28")


def test_missing_and_placeholder_timestamps_are_rejected():
    for value in (None, "", "None", "n/a", "not-a-date"):
        assert _parse_timestamp(value) == ""


def test_epoch_placeholder_is_rejected():
    """A 1601/1970 stamp means 'not recorded', not 'happened long ago'."""
    assert _parse_timestamp("1601-01-01T00:00:00+00:00") == ""


# ------------------------------------------------------------------
# Deduplication
# ------------------------------------------------------------------

def _event(plugin, evidence_id, description="process started: smss.exe (PID 956)"):
    return TimelineEvent(
        timestamp="2026-08-28T05:23:07+00:00",
        plugin=plugin,
        description=description,
        evidence_id=evidence_id,
        sources=[plugin],
    )


def test_same_event_from_several_plugins_collapses():
    """
    pslist, psscan and pstree all carry process start times. Undeduplicated,
    every boot appears three times and reads as three times the activity.
    """
    merged = _deduplicate(
        [
            _event("windows.pslist", 34),
            _event("windows.psscan", 20505),
            _event("windows.pstree", 735),
        ]
    )
    assert len(merged) == 1
    assert len(merged[0].sources) == 3
    assert merged[0].evidence_id == 34


def test_distinct_events_are_preserved():
    merged = _deduplicate(
        [
            _event("windows.pslist", 34),
            _event("windows.pslist", 35, "process started: csrss.exe (PID 1392)"),
        ]
    )
    assert len(merged) == 2


# ------------------------------------------------------------------
# Timeline rendering
# ------------------------------------------------------------------

def test_timeline_record_ids_are_not_bracketed():
    """
    Rendering these as "[evidence 32]" taught the model to cite database
    identifiers as citation numbers: it emitted "[20224]", outside the
    numbered range, which was silently dropped and left the answer far less
    supported than it looked.
    """
    block = format_timeline([_event("windows.pslist", 20224)], limit=40)
    assert "[20224]" not in block
    assert "record #20224" in block
    assert "NOT citation numbers" in block


def test_timeline_states_malfind_is_absent_and_why():
    block = format_timeline([_event("windows.pslist", 1)], limit=40)
    assert "malfind regions carry no" in block


def test_empty_timeline_forbids_implying_a_sequence():
    block = format_timeline([], limit=40)
    assert "No timestamped evidence" in block
    assert "rather than implying a sequence" in block


def test_truncated_timeline_says_the_gap_is_not_quiet():
    events = [_event("windows.pslist", i, f"event {i}") for i in range(40)]
    block = format_timeline(events, limit=40)
    assert "NOT a quiet period" in block


# ------------------------------------------------------------------
# Corpus overview
# ------------------------------------------------------------------

def _overview(**kwargs) -> CorpusOverview:
    defaults = {
        "total_rows": 326506,
        "plugins": [
            PluginSummary("windows.malfind", 8912, {"high": 8912}),
            PluginSummary("windows.handles", 146094, {"low": 146094}),
        ],
    }
    defaults.update(kwargs)
    return CorpusOverview(**defaults)


def test_overview_reports_exact_totals_not_a_sample():
    block = format_overview(_overview())
    assert "326,506" in block
    assert "complete counts, not a sample" in block


def test_overview_of_empty_investigation():
    assert "No completed plugin evidence" in format_overview(CorpusOverview())


def test_unavailable_plugins_are_named_as_unexamined():
    block = format_overview(
        _overview(unavailable=[("windows.memmap", "acquisition interrupted")])
    )
    assert "windows.memmap" in block
    assert "must not report the associated activity as absent" in block


def test_completed_plugins_drive_retrieval_breadth():
    assert _overview().completed_plugins == (
        "windows.malfind",
        "windows.handles",
    )


# ------------------------------------------------------------------
# Malfind severity qualification
# ------------------------------------------------------------------

def test_malfind_total_is_not_presented_as_an_incident_count():
    """
    The classifier's malfind rule matches unconditionally, so the stored
    high-severity count is just the number of rows the plugin returned.
    """
    block = format_overview(
        _overview(
            malfind=MalfindBreakdown(
                total=8912,
                private=56,
                mapped=8856,
                processes=33,
                top_processes=[("SupportAssistA", 22664, 1762)],
                private_processes=[("MsMpEng.exe", 5864, 13)],
            )
        )
    )
    assert "not 8912 separate confirmed intrusions" in block
    assert "property of the classification rule" in block
    assert "Do NOT report the total as a count of intrusions" in block


def test_malfind_split_between_private_and_mapped_is_reported():
    block = format_overview(
        _overview(
            malfind=MalfindBreakdown(
                total=8912, private=56, mapped=8856, processes=33
            )
        )
    )
    assert "56" in block
    assert "8,856" in block
    assert "just-in-time compiler" in block


def test_overview_without_malfind_omits_the_qualification():
    block = format_overview(_overview(malfind=None))
    assert "SEVERITY QUALIFICATION" not in block
