"""
Deterministic question routing for the department's forensic question set.

Semantic similarity alone is unreliable for these questions: asking about
process relationships can rank a `handles` record above the `pstree` record
that actually answers it, simply because 146k handle rows dominate the
corpus. This module maps a question to the Volatility plugins that are
authoritative for it, so retrieval can pull from those sources directly and
let similarity search operate within them rather than across everything.

It also reports, per mapped source, whether that source is actually usable
for this investigation. That distinction is the point: a plugin that ran and
found nothing supports a negative finding, whereas a plugin that never ran
cannot. Without it the model sees only whatever evidence happened to be
retrieved and quietly concludes absence — which is how "no code injection
was found" was previously asserted with full confidence on an investigation
where the only plugin capable of detecting injection had timed out.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.memory_dump import MemoryDump
from app.models.plugin_execution import PluginExecution
from app.models.plugin_result import PluginResult

logger = get_logger(__name__)


# ==============================================================================
# Coverage states
# ==============================================================================

AVAILABLE = "AVAILABLE"
"""Plugin completed and produced evidence. Supports positive and negative findings."""

RAN_EMPTY = "RAN-EMPTY"
"""Plugin completed but produced no rows. The check was genuinely performed."""

UNAVAILABLE = "UNAVAILABLE"
"""Plugin failed or never ran. Cannot support a negative finding."""


@dataclass(frozen=True)
class SourceCoverage:
    """Availability of one mapped evidence source for one investigation."""

    plugin: str
    state: str
    rows: int = 0
    detail: str = ""

    @property
    def usable(self) -> bool:
        """True when the source can back a finding either way."""

        return self.state in (AVAILABLE, RAN_EMPTY)


# ==============================================================================
# Question routes
# ==============================================================================


@dataclass(frozen=True)
class QuestionRoute:
    """One entry of the department's question-to-evidence mapping."""

    qid: str
    summary: str
    plugins: tuple[str, ...]
    keywords: tuple[str, ...]
    # Questions answered from correlation across everything rather than a
    # specific plugin set.
    synthesis: bool = False
    # Questions that require evidence this platform does not collect.
    out_of_scope: str = ""
    # Questions answered partly by the deterministic known-tool scan
    # (app/services/tool_signatures.py) rather than by retrieval alone.
    tool_scan: bool = False
    required_terms: tuple[str, ...] = field(default_factory=tuple)


ROUTES: tuple[QuestionRoute, ...] = (
    QuestionRoute(
        qid="Q1",
        summary="Suspicious processes, abnormal execution and process relationships",
        plugins=(
            "windows.pslist", "windows.pstree", "windows.psscan",
            "windows.cmdline", "windows.cmdscan",
        ),
        keywords=(
            "suspicious process", "malicious process", "process relationship",
            "parent", "child", "process tree", "hidden process",
            "unlinked", "abnormal process", "process execution",
            "what processes", "which processes", "running process",
        ),
    ),
    QuestionRoute(
        qid="Q2",
        summary="Injected executable memory, process hollowing, in-memory execution",
        plugins=(
            "windows.malfind", "windows.vadinfo", "windows.vadwalk",
            "windows.memmap", "windows.dlllist",
        ),
        keywords=(
            "inject", "injection", "hollow", "process hollowing", "shellcode",
            "rwx", "in-memory execution", "injected code", "injected memory",
            "executable memory", "anomalous vad",
        ),
    ),
    QuestionRoute(
        qid="Q3",
        summary="LSASS and credential-access activity",
        plugins=(
            "windows.pslist", "windows.dumpfiles", "windows.memmap",
            "windows.handles",
        ),
        keywords=(
            "lsass", "credential access", "credential dump",
            "credential theft", "lsass access",
        ),
    ),
    QuestionRoute(
        qid="Q4",
        summary="PowerShell, CMD, WMI, scripting and command execution",
        plugins=("windows.cmdline", "windows.cmdscan", "windows.consoles"),
        keywords=(
            "powershell", "cmd.exe", "wmi", "script", "encoded command",
            "-enc", "iex", "download cradle", "lolbin", "command execution",
            "command line",
        ),
    ),
    QuestionRoute(
        qid="Q5",
        summary="Shell/command history before acquisition",
        plugins=("windows.cmdscan", "windows.consoles"),
        keywords=(
            "command history", "shell history", "commands executed",
            "console history", "typed command", "before acquisition",
        ),
    ),
    QuestionRoute(
        qid="Q6",
        summary="Network connections correlated with processes",
        plugins=("windows.netscan", "windows.netstat", "windows.pslist"),
        keywords=(
            "network connection", "remote ip", "listening", "socket",
            "established connection", "c2", "command and control",
            "outbound", "port", "connections",
        ),
    ),
    QuestionRoute(
        qid="Q7",
        summary="Correlation with a known malicious IP range",
        plugins=("windows.netscan", "windows.netstat"),
        keywords=(
            "109.21.12", "malicious range", "known malicious ip",
            "ioc", "infrastructure",
        ),
    ),
    QuestionRoute(
        qid="Q8",
        summary="Headless Chrome and browser automation",
        plugins=(
            "windows.pslist", "windows.pstree", "windows.cmdline",
            "windows.dlllist",
        ),
        keywords=(
            "headless", "chrome", "chromedriver", "remote-debugging",
            "browser automation", "selenium", "puppeteer",
        ),
    ),
    QuestionRoute(
        qid="Q9",
        summary="Browser authentication / M365 session artifacts",
        plugins=(),
        keywords=(
            "m365", "microsoft 365", "onedrive", "sharepoint", "teams",
            "mailbox", "outlook", "session cookie", "auth token",
            "browser authentication",
        ),
        out_of_scope=(
            "This question requires disk and browser forensics (profile "
            "databases, cookie stores, token caches), which this platform "
            "does not collect. Memory-only evidence cannot answer it, and "
            "inferring an answer from unrelated artifacts would be "
            "misleading."
        ),
    ),
    QuestionRoute(
        qid="Q10",
        summary="Malware or suspicious executables communicating externally",
        plugins=(
            "windows.netscan", "windows.pslist", "windows.dlllist",
            "windows.malfind",
        ),
        keywords=(
            "malware communicating", "suspicious executable",
            "external infrastructure", "beacon", "callback",
            "executable connection",
        ),
    ),
    QuestionRoute(
        qid="Q11",
        summary="Mimikatz, Potato-family tools, credential/privilege escalation",
        plugins=(
            "windows.malfind", "windows.vadyarascan", "windows.cmdline",
        ),
        keywords=(
            "mimikatz", "potato", "juicypotato", "rottenpotato",
            "privilege escalation", "token manipulation",
            "credential dumping", "sekurlsa",
        ),
    ),
    QuestionRoute(
        qid="Q12",
        summary="APT28 / tunnel implant indicators",
        plugins=(
            "windows.netscan", "windows.pslist", "windows.malfind",
            "windows.vadyarascan",
        ),
        keywords=(
            "apt28", "fancy bear", "tunnel implant", "implant",
            "attribution", "threat actor",
        ),
    ),
    QuestionRoute(
        qid="Q13",
        summary="CoinMiner / cryptomining activity",
        plugins=(
            "windows.pslist", "windows.pstree", "windows.netscan",
            "windows.cmdline", "windows.vadyarascan",
        ),
        keywords=(
            "coinminer", "cryptomining", "crypto mining", "miner",
            "xmrig", "stratum", "mining pool", "wallet",
        ),
    ),
    QuestionRoute(
        qid="Q14",
        summary="Persistence, autoruns and scheduled execution",
        plugins=(
            "windows.svcscan", "windows.registry.printkey",
            "windows.registry.hivelist", "windows.pslist",
        ),
        keywords=(
            "persistence", "autorun", "run key", "runonce",
            "scheduled task", "startup", "service", "survive reboot",
            "wmi persistence",
        ),
    ),
    QuestionRoute(
        qid="Q15",
        summary="Remote-access, lateral-movement and administration tools",
        plugins=(
            "windows.pslist", "windows.cmdline", "windows.netscan",
            "windows.filescan",
        ),
        keywords=(
            "remote access", "lateral movement", "anydesk", "psexec",
            "rdp", "winscp", "rclone", "nmap", "angry ip",
            "administration tool", "remote execution", "teamviewer",
            "remote desktop", "tunnel", "ngrok", "known tool",
        ),
        tool_scan=True,
    ),
    QuestionRoute(
        qid="Q16",
        summary="Offensive-security tools and post-exploitation frameworks",
        plugins=(
            "windows.vadyarascan", "windows.malfind", "windows.cmdline",
            "windows.pslist",
        ),
        keywords=(
            "cobalt strike", "cobaltstrike", "metasploit", "meterpreter",
            "beacon", "post-exploitation", "offensive security",
            "c2 framework", "loader",
        ),
    ),
    QuestionRoute(
        qid="Q17",
        summary="Suspicious file, DLL and executable artifacts",
        plugins=(
            "windows.dlllist", "windows.modules", "windows.filescan",
            "windows.dumpfiles",
        ),
        keywords=(
            "suspicious file", "suspicious dll", "unsigned", "non-standard dll",
            "unusual module", "file artifact", "executable artifact",
            "dll.dat", "extraction", "hash analysis",
        ),
    ),
    QuestionRoute(
        qid="Q18",
        summary="YARA-based malware triage",
        plugins=("windows.vadyarascan",),
        keywords=(
            "yara", "signature match", "rule match", "malware triage",
            "signature triage",
        ),
    ),
    QuestionRoute(
        qid="Q19",
        summary="Compromised accounts / unauthorized access",
        plugins=(
            "windows.getsids", "windows.pslist", "windows.netscan",
            "windows.registry.printkey",
        ),
        keywords=(
            "compromised account", "unauthorized access", "account",
            "privilege context", "logon", "sid", "user account",
        ),
    ),
    QuestionRoute(
        qid="Q20",
        summary="Integrated incident timeline and forensic assessment",
        plugins=(),
        keywords=(
            "timeline", "attack chain", "integrated assessment",
            "overall assessment", "incident summary", "full picture",
            "correlate everything",
        ),
        synthesis=True,
    ),
)


_WORD_RE = re.compile(r"[a-z0-9.+_-]+")


def _normalise(text: str) -> str:
    return " ".join(_WORD_RE.findall(text.lower()))


def match_route(question: str) -> QuestionRoute | None:
    """
    Return the best-matching route for a question, or ``None``.

    Scoring favours longer keyword phrases, so "process hollowing" outranks a
    bare "process" hit and the question lands on Q2 rather than Q1. Returning
    ``None`` is normal and means the caller should fall back to semantic
    search — the routing table covers the department's fixed question set,
    not every question an investigator might ask.
    """

    haystack = _normalise(question)

    if not haystack:
        return None

    best: QuestionRoute | None = None
    best_score = 0

    for route in ROUTES:

        score = 0

        for keyword in route.keywords:
            if _normalise(keyword) in haystack:
                # Longer phrases are stronger evidence of intent.
                score += len(keyword.split()) * 10 + len(keyword)

        if score > best_score:
            best = route
            best_score = score

    if best is not None:
        logger.info(
            "Question routed to %s (%s), score=%d",
            best.qid,
            best.summary,
            best_score,
        )

    return best


# ==============================================================================
# Coverage assessment
# ==============================================================================


def assess_coverage(
    session: Session,
    investigation_id: str,
    plugins: tuple[str, ...],
) -> list[SourceCoverage]:
    """
    Classify each mapped plugin as AVAILABLE, RAN-EMPTY or UNAVAILABLE.

    A plugin absent from ``plugin_executions`` never ran for this
    investigation; one present but not ``completed`` was attempted and did
    not finish. Both are UNAVAILABLE, but the reported detail differs so the
    model can say which, and the investigator can act on it.
    """

    if not plugins:
        return []

    rows = session.execute(
        select(
            PluginExecution.plugin_name,
            PluginExecution.execution_status,
            PluginExecution.error_message,
            func.count(PluginResult.id),
        )
        .select_from(MemoryDump)
        .join(
            PluginExecution,
            PluginExecution.memory_dump_id == MemoryDump.id,
        )
        .outerjoin(
            PluginResult,
            PluginResult.plugin_execution_id == PluginExecution.id,
        )
        .where(MemoryDump.investigation_id == investigation_id)
        .where(PluginExecution.plugin_name.in_(plugins))
        .group_by(PluginExecution.id)
    ).all()

    observed: dict[str, tuple[str, str | None, int]] = {}

    for name, status, error, count in rows:
        # Keep the most informative execution when a plugin ran more than
        # once: a completed run with rows beats an earlier failure.
        previous = observed.get(name)

        if previous is None or (status == "completed" and count >= previous[2]):
            observed[name] = (status, error, count)

    coverage: list[SourceCoverage] = []

    for plugin in plugins:

        entry = observed.get(plugin)

        if entry is None:
            coverage.append(
                SourceCoverage(
                    plugin=plugin,
                    state=UNAVAILABLE,
                    detail="not run for this investigation",
                )
            )
            continue

        status, error, count = entry

        if status != "completed":
            reason = (error or "").strip().splitlines()
            summary = reason[-1][:160] if reason else f"execution {status}"
            coverage.append(
                SourceCoverage(
                    plugin=plugin,
                    state=UNAVAILABLE,
                    rows=count,
                    detail=f"attempted; {summary}",
                )
            )
            continue

        if count == 0:
            coverage.append(
                SourceCoverage(
                    plugin=plugin,
                    state=RAN_EMPTY,
                    detail="ran successfully and produced no records",
                )
            )
            continue

        coverage.append(
            SourceCoverage(
                plugin=plugin,
                state=AVAILABLE,
                rows=count,
                detail=f"{count:,} records",
            )
        )

    return coverage


def format_coverage(
    route: QuestionRoute,
    coverage: list[SourceCoverage],
) -> str:
    """
    Render the coverage block that precedes the evidence in the prompt.
    """

    lines = [
        "EVIDENCE COVERAGE FOR THIS QUESTION",
        f"Question type: {route.qid} — {route.summary}",
        "",
        "Expected evidence sources and their availability:",
    ]

    for entry in coverage:
        lines.append(
            f"  {entry.plugin:32} {entry.state:12} {entry.detail}"
        )

    unusable = [entry for entry in coverage if not entry.usable]

    lines.append("")

    if unusable:
        names = ", ".join(entry.plugin for entry in unusable)
        lines.append(
            "IMPORTANT: the sources marked UNAVAILABLE were not searched. "
            f"Findings that depend on {names} cannot be confirmed or ruled "
            "out. Do not state that the associated activity is absent; "
            "report the check as not performed."
        )
        lines.append("")
        lines.append(
            "REQUIRED: your GAPS section must name every source listed as "
            f"UNAVAILABLE above ({names}) and state what it would have shown. "
            "Writing \"None.\" in GAPS is incorrect for this question, "
            "because the evidence coverage above is incomplete."
        )
    else:
        lines.append(
            "All expected sources for this question were searched, so an "
            "absence of matching records is a meaningful negative finding."
        )

    return "\n".join(lines)


__all__ = [
    "AVAILABLE",
    "RAN_EMPTY",
    "UNAVAILABLE",
    "QuestionRoute",
    "ROUTES",
    "SourceCoverage",
    "assess_coverage",
    "format_coverage",
    "match_route",
]
