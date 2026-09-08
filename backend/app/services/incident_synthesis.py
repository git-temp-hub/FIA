"""
Corpus overview and timeline construction for the integrated assessment (Q20).

Why this exists
---------------
Q20 asks what happened, in what order, and what the overall conclusion is.
Answered through ordinary retrieval it produced a confident all-clear: six
``pslist`` rows -- System, Registry, smss.exe, csrss.exe -- out of 326,506,
never reaching malfind, netscan or the YARA results, concluding "no malicious
activity is detected" at confidence 75. Sampling six rows cannot support a
statement about a whole investigation, and the sample gave no hint that
anything was missing.

A synthesis question needs the shape of the corpus, not a sample of it. The
counts here are computed over every row and are exact; the model narrates them
rather than inferring them from whatever happened to be retrieved.

Severity qualification
----------------------
The stored ``risk_level`` cannot be read as a count of incidents. The malfind
rule (``_mf_01`` in the evidence classifier) matches unconditionally --
"a malfind result is an injected-memory indicator by definition" -- so every
malfind row is high severity and the count is just the number of rows the
plugin returned.

That distinction matters most here, because a synthesis answer is where a
mislabelled corpus does the most damage. On D2F9, 8,856 of 8,912 high-severity
malfind rows describe *mapped* regions (``privatememory: 0``), the pattern
produced by .NET JIT compilation, and the largest holders are signed Dell,
Intel and Microsoft software. Injected code is characteristically *private*
and committed; only 56 rows match that shape.

Nothing is reclassified or hidden: stored severities are untouched and every
row remains retrievable. The overview reports the distribution alongside the
label so the reader sees both, and says plainly that the stored severity does
not account for it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.memory_dump import MemoryDump
from app.models.plugin_execution import PluginExecution
from app.models.plugin_result import PluginResult

logger = get_logger(__name__)


# Plugins carrying a usable event time, and the field holding it.
TIMESTAMP_FIELDS: dict[str, tuple[str, ...]] = {
    "windows.pslist": ("createtime",),
    "windows.psscan": ("createtime",),
    "windows.pstree": ("createtime",),
    "windows.netscan": ("created",),
    "windows.netstat": ("created",),
}

MAX_TIMELINE_EVENTS = 40


# ==============================================================================
# Corpus overview
# ==============================================================================


@dataclass
class PluginSummary:
    """Row and risk counts for one plugin."""

    plugin: str
    rows: int = 0
    risk: dict[str, int] = field(default_factory=dict)

    @property
    def high(self) -> int:
        return self.risk.get("high", 0)

    @property
    def medium(self) -> int:
        return self.risk.get("medium", 0)


@dataclass
class MalfindBreakdown:
    """
    How malfind's high-severity rows divide by memory type.

    ``private`` regions are committed and process-private, the shape injected
    code takes. ``mapped`` regions are backed elsewhere and are what a JIT
    compiler produces in normal operation.
    """

    total: int = 0
    private: int = 0
    mapped: int = 0
    processes: int = 0
    top_processes: list[tuple[str, int, int]] = field(default_factory=list)
    private_processes: list[tuple[str, int, int]] = field(default_factory=list)


@dataclass
class CorpusOverview:
    """Exact counts across an entire investigation."""

    total_rows: int = 0
    plugins: list[PluginSummary] = field(default_factory=list)
    malfind: MalfindBreakdown | None = None
    # Plugins attempted but not completed. For a synthesis question this is
    # the coverage report: a whole-incident conclusion has to say which parts
    # of the host were never examined.
    unavailable: list[tuple[str, str]] = field(default_factory=list)

    @property
    def completed_plugins(self) -> tuple[str, ...]:
        return tuple(entry.plugin for entry in self.plugins)

    @property
    def total_high(self) -> int:
        return sum(entry.high for entry in self.plugins)

    @property
    def total_medium(self) -> int:
        return sum(entry.medium for entry in self.plugins)


def _completed_executions(
    session: Session,
    investigation_id: str,
) -> dict[str, int]:
    """Map plugin name to execution id for completed runs."""

    statement = (
        select(PluginExecution.plugin_name, PluginExecution.id)
        .select_from(MemoryDump)
        .join(PluginExecution, PluginExecution.memory_dump_id == MemoryDump.id)
        .where(MemoryDump.investigation_id == investigation_id)
        .where(PluginExecution.execution_status == "completed")
    )

    return {name: identifier for name, identifier in session.execute(statement)}


def build_overview(
    session: Session,
    investigation_id: str,
) -> CorpusOverview:
    """Compute exact row and risk counts across the whole investigation."""

    executions = _completed_executions(session, investigation_id)

    if not executions:
        return CorpusOverview()

    counts = session.execute(
        select(
            PluginExecution.plugin_name,
            PluginResult.risk_level,
            func.count(PluginResult.id),
        )
        .select_from(PluginExecution)
        .join(
            PluginResult,
            PluginResult.plugin_execution_id == PluginExecution.id,
        )
        .where(PluginExecution.id.in_(tuple(executions.values())))
        .group_by(PluginExecution.plugin_name, PluginResult.risk_level)
    ).all()

    summaries: dict[str, PluginSummary] = {}
    total = 0

    for plugin, risk, count in counts:
        summary = summaries.setdefault(plugin, PluginSummary(plugin))
        summary.rows += count
        summary.risk[str(risk or "unclassified")] = count
        total += count

    failed = session.execute(
        select(PluginExecution.plugin_name, PluginExecution.error_message)
        .select_from(MemoryDump)
        .join(PluginExecution, PluginExecution.memory_dump_id == MemoryDump.id)
        .where(MemoryDump.investigation_id == investigation_id)
        .where(PluginExecution.execution_status != "completed")
    ).all()

    overview = CorpusOverview(
        total_rows=total,
        plugins=sorted(
            summaries.values(),
            key=lambda entry: (-entry.high, -entry.medium, entry.plugin),
        ),
        malfind=_malfind_breakdown(session, executions.get("windows.malfind")),
        unavailable=sorted(
            {
                (
                    name,
                    ((error or "").strip().splitlines() or ["did not complete"])[-1][:120],
                )
                for name, error in failed
                if name not in summaries
            }
        ),
    )

    logger.info(
        "Corpus overview for '%s': %d rows, %d high, %d medium.",
        investigation_id,
        overview.total_rows,
        overview.total_high,
        overview.total_medium,
    )

    return overview


def _malfind_breakdown(
    session: Session,
    execution_id: int | None,
) -> MalfindBreakdown | None:
    """Split malfind's high-severity rows into private and mapped regions."""

    if execution_id is None:
        return None

    statement = (
        select(PluginResult.artifact_value)
        .where(PluginResult.plugin_execution_id == execution_id)
        .where(PluginResult.risk_level == "high")
    )

    breakdown = MalfindBreakdown()
    per_process: dict[tuple, int] = {}
    per_private: dict[tuple, int] = {}

    for (raw,) in session.execute(statement):

        try:
            value = json.loads(raw)
        except (TypeError, ValueError):
            continue

        if not isinstance(value, dict):
            continue

        breakdown.total += 1

        name = str(value.get("process") or "unknown")
        pid = value.get("pid")
        key = (name, pid)

        per_process[key] = per_process.get(key, 0) + 1

        if str(value.get("privatememory")) == "1":
            breakdown.private += 1
            per_private[key] = per_private.get(key, 0) + 1
        else:
            breakdown.mapped += 1

    if not breakdown.total:
        return None

    breakdown.processes = len(per_process)
    breakdown.top_processes = [
        (name, pid, count)
        for (name, pid), count in sorted(
            per_process.items(), key=lambda item: -item[1]
        )[:8]
    ]
    breakdown.private_processes = [
        (name, pid, count)
        for (name, pid), count in sorted(
            per_private.items(), key=lambda item: -item[1]
        )[:8]
    ]

    return breakdown


# ==============================================================================
# Timeline
# ==============================================================================


@dataclass
class TimelineEvent:
    """One dated event drawn from the evidence."""

    timestamp: str
    plugin: str
    description: str
    evidence_id: int
    # Plugins reporting this same event. pslist, psscan and pstree all carry
    # process start times, so an undeduplicated timeline lists every boot
    # three times and reads as three times the activity.
    sources: list[str] = field(default_factory=list)

    @property
    def sort_key(self) -> str:
        return self.timestamp


def _parse_timestamp(value) -> str:
    """Normalise a timestamp to a sortable string, or "" if unusable."""

    text = str(value or "").strip()

    if not text or text.lower() in ("none", "null", "n/a"):
        return ""

    # Volatility emits ISO-8601; keep anything already in that shape and
    # reject the placeholder epoch values that mean "not recorded".
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return ""

    if parsed.year < 1990:
        return ""

    return parsed.isoformat()


def _describe(plugin: str, value: dict) -> str:
    """One-line description of a timestamped record."""

    pid = value.get("pid")

    if plugin in ("windows.pslist", "windows.psscan", "windows.pstree"):
        return (
            f"process started: {value.get('imagefilename') or 'unknown'} "
            f"(PID {pid}, PPID {value.get('ppid')})"
        )

    if plugin in ("windows.netscan", "windows.netstat"):
        return (
            f"connection {value.get('proto') or ''} "
            f"{value.get('localaddr')}:{value.get('localport')} -> "
            f"{value.get('foreignaddr')}:{value.get('foreignport')} "
            f"[{value.get('state') or 'n/a'}] (PID {pid})"
        ).strip()

    return f"{plugin} record (PID {pid})"


def _deduplicate(events: list[TimelineEvent]) -> list[TimelineEvent]:
    """
    Collapse the same event reported by several plugins into one entry.

    A process start appears in pslist, psscan and pstree alike. Listing it
    three times inflates the apparent volume of activity, which is exactly the
    kind of distortion a synthesis answer would then narrate.
    """

    merged: dict[tuple[str, str], TimelineEvent] = {}

    for event in events:

        key = (event.timestamp, event.description)
        existing = merged.get(key)

        if existing is None:
            merged[key] = event
            continue

        for source in event.sources:
            if source not in existing.sources:
                existing.sources.append(source)

    return list(merged.values())


def build_timeline(
    session: Session,
    investigation_id: str,
    limit: int = MAX_TIMELINE_EVENTS,
) -> list[TimelineEvent]:
    """
    Build a chronological event list from the timestamped evidence.

    Only plugins that actually carry a time are consulted. malfind is
    deliberately absent: its rows have no timestamp, and dating an injected
    region by its host process's start time would invent an ordering the
    evidence does not support.
    """

    executions = _completed_executions(session, investigation_id)

    events: list[TimelineEvent] = []

    for plugin, fields in TIMESTAMP_FIELDS.items():

        execution_id = executions.get(plugin)

        if execution_id is None:
            continue

        statement = (
            select(PluginResult.id, PluginResult.artifact_value)
            .where(PluginResult.plugin_execution_id == execution_id)
        )

        for identifier, raw in session.execute(statement):

            try:
                value = json.loads(raw)
            except (TypeError, ValueError):
                continue

            if not isinstance(value, dict):
                continue

            stamp = ""
            for candidate in fields:
                stamp = _parse_timestamp(value.get(candidate))
                if stamp:
                    break

            if not stamp:
                continue

            events.append(
                TimelineEvent(
                    timestamp=stamp,
                    plugin=plugin,
                    description=_describe(plugin, value),
                    evidence_id=identifier,
                    sources=[plugin],
                )
            )

    events = _deduplicate(events)
    events.sort(key=lambda event: event.sort_key)

    if len(events) <= limit:
        return events

    # Keep both ends: the earliest activity establishes the baseline and the
    # latest is nearest to acquisition. Dropping the middle is stated in the
    # rendered block so the gap is never mistaken for quiet time.
    half = limit // 2
    return events[:half] + events[-half:]


# ==============================================================================
# Rendering
# ==============================================================================


def format_overview(overview: CorpusOverview) -> str:
    """Render the corpus overview block."""

    if not overview.total_rows:
        return (
            "CORPUS OVERVIEW\nNo completed plugin evidence exists for this "
            "investigation."
        )

    lines = [
        "CORPUS OVERVIEW (exact counts across the whole investigation)",
        f"{overview.total_rows:,} evidence records from "
        f"{len(overview.plugins)} plugins. These are complete counts, not a "
        "sample: use them for any statement about scale, and cite individual "
        "records only for specific claims.",
        "",
        f"{'plugin':32} {'rows':>9} {'high':>7} {'medium':>7}",
    ]

    for entry in overview.plugins:
        lines.append(
            f"{entry.plugin:32} {entry.rows:>9,} {entry.high:>7,} "
            f"{entry.medium:>7,}"
        )

    if overview.unavailable:
        lines.append("")
        lines.append("Plugins that did NOT produce evidence for this host:")
        for name, reason in overview.unavailable:
            lines.append(f"  {name:32} {reason}")
        lines.append(
            "These areas were not examined. An integrated conclusion must say "
            "so and must not report the associated activity as absent."
        )

    if overview.malfind is not None:
        lines.append("")
        lines.extend(_format_malfind(overview.malfind))

    return "\n".join(lines)


def _format_malfind(breakdown: MalfindBreakdown) -> list[str]:
    """Render the malfind severity qualification."""

    lines = [
        "SEVERITY QUALIFICATION — windows.malfind",
        f"All {breakdown.total:,} malfind rows are stored as high severity. "
        "That is a property of the classification rule, which treats every "
        "malfind result as an injected-memory indicator by definition; it is "
        "not {n} separate confirmed intrusions.".format(n=breakdown.total),
        "",
        f"  regions in private committed memory : {breakdown.private:,}",
        f"  regions in mapped memory            : {breakdown.mapped:,}",
        f"  distinct processes                  : {breakdown.processes:,}",
    ]

    if breakdown.top_processes:
        lines.append("")
        lines.append("  largest holders (all region types):")
        for name, pid, count in breakdown.top_processes:
            lines.append(f"      {name} (PID {pid}): {count:,}")

    if breakdown.private_processes:
        lines.append("")
        lines.append("  processes holding PRIVATE committed regions:")
        for name, pid, count in breakdown.private_processes:
            lines.append(f"      {name} (PID {pid}): {count:,}")

    lines.append("")
    lines.append(
        "Injected code is characteristically private and committed. Regions "
        "in mapped memory are what a just-in-time compiler produces in normal "
        "operation, so a large mapped count in managed-code processes is "
        "expected rather than incriminating. Do NOT report the total as a "
        "count of intrusions or compromised processes. Where you discuss "
        "these regions, say which of the two kinds you mean, and treat the "
        "mapped majority as unexplained-but-ordinary unless other evidence "
        "supports otherwise."
    )

    return lines


def format_timeline(events: list[TimelineEvent], limit: int) -> str:
    """Render the timeline block."""

    if not events:
        return (
            "INCIDENT TIMELINE\nNo timestamped evidence is available, so no "
            "ordering can be established. Say so rather than implying a "
            "sequence."
        )

    lines = [
        "INCIDENT TIMELINE (from timestamped evidence, earliest first)",
    ]

    if len(events) >= limit:
        lines.append(
            "Showing the earliest and latest events only; the middle of the "
            "sequence is omitted for length and is NOT a quiet period."
        )

    lines.append("")

    for event in events:
        corroboration = (
            f" (+{len(event.sources) - 1} corroborating source)"
            if len(event.sources) > 1
            else ""
        )
        # No identifier at all. Rendered as "[evidence 32]" these taught the
        # model to cite database identifiers as citation numbers; rendered as
        # "(record #32)" alongside an instruction never to bracket them, it
        # still emitted "[20226]", leaving that claim uncited. Removing the
        # number removes the failure mode, which beats instructing against it.
        lines.append(
            f"  {event.timestamp}  {event.description}{corroboration}"
        )

    lines.append("")
    lines.append(
        "Timeline entries carry no citation number and are not themselves "
        "citable. Use them for ordering, and cite the numbered evidence "
        "blocks supplied further below for specific claims."
    )
    lines.append(
        "Process start times and connection times come from memory "
        "structures resident at acquisition. malfind regions carry no "
        "timestamp and are deliberately absent: dating them by their host "
        "process's start time would invent an ordering the evidence does not "
        "support. Do not place them on this timeline."
    )

    return "\n".join(lines)


__all__ = [
    "CorpusOverview",
    "MalfindBreakdown",
    "MAX_TIMELINE_EVENTS",
    "PluginSummary",
    "TimelineEvent",
    "build_overview",
    "build_timeline",
    "format_overview",
    "format_timeline",
]
