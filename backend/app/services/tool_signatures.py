"""
Known-tool signature matching over evidence already in the database.

Q15 asks which remote-access, lateral-movement and administration tools were
present. Semantic retrieval answers that badly: the phrase "remote access"
matches prose about remote procedure calls far more readily than it matches a
row whose only distinguishing feature is the literal string ``anydesk.exe``.
This module does the lookup deterministically against evidence that has
already been collected — it runs no Volatility plugin and needs no dump.

Three findings from the D2F9 corpus shaped the design:

* Substring matching is unusable. A trial catalogue containing "assist"
  matched 312 rows, every one of them Dell SupportAssist — a legitimate OEM
  utility. Matching is therefore on exact executable names and anchored path
  fragments, never on loose substrings.

* Presence on disk is not execution. ``mstsc.exe`` appears in ``filescan``
  three times on a host that never ran it: it ships with Windows and sits in
  System32 on every installation. Built-in tooling is reported only when it
  is actually running, and a third-party binary found only on disk is
  reported as presence, not use.

* Process names arrive truncated. The EPROCESS ``ImageFileName`` field is
  fixed-width, so ``CodeMeterCC.exe`` is stored as ``CodeMeterCC.ex``. An
  exact comparison against a catalogue entry longer than the field silently
  never fires; ``advanced_ip_scanner.exe`` could never have matched.

Matches are leads requiring corroboration, not conclusions. A remote-access
tool is not itself evidence of compromise — helpdesks deploy them
legitimately — so the finding reports what was observed and how strongly,
and leaves the interpretation to the investigator.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.memory_dump import MemoryDump
from app.models.plugin_execution import PluginExecution
from app.models.plugin_result import PluginResult

logger = get_logger(__name__)


# The EPROCESS ImageFileName field holds 15 bytes; Volatility renders the
# printable prefix, which is 14 characters for a name that fills the field.
_TRUNCATED_NAME_LENGTH = 14


# ==============================================================================
# Evidence strength
# ==============================================================================

EXECUTED = "EXECUTED"
"""Observed as a running process, or with a recovered command line."""

ON_DISK = "ON-DISK"
"""Binary present in the file system. Presence is not proof of execution."""

NETWORK = "NETWORK"
"""A connection on a port this tool characteristically uses. Weak alone."""

_STRENGTH_ORDER = {EXECUTED: 0, ON_DISK: 1, NETWORK: 2}


# ==============================================================================
# Catalogue
# ==============================================================================


@dataclass(frozen=True)
class ToolSignature:
    """One known tool and the artifacts that identify it."""

    name: str
    category: str
    # Exact executable names, compared case-insensitively and against the
    # truncated process-name field.
    processes: tuple[str, ...] = ()
    # Anchored path fragments, e.g. "\\anydesk\\". Matched case-insensitively.
    paths: tuple[str, ...] = ()
    # Exact tokens that identify the tool on a command line. Use only
    # distinctive tokens: a loose one such as "\\\\" matches local named
    # pipes ("\\\\.\\pipe\\...") and produces confident nonsense.
    cmdline_tokens: tuple[str, ...] = ()
    # Pattern for cases a token cannot express, such as "a UNC host that is
    # not the local device". Matched case-insensitively against the args.
    cmdline_regex: str = ""
    # Ports the tool characteristically uses. Corroborating only: a port is
    # never sufficient on its own, since anything may bind any port.
    ports: tuple[int, ...] = ()
    # Ships with Windows. Presence on disk carries no information, so these
    # are reported only when observed executing.
    builtin: bool = False
    note: str = ""


REMOTE_ACCESS = "remote access"
LATERAL_MOVEMENT = "lateral movement"
TUNNELING = "tunnelling / proxying"
TRANSFER = "file transfer / staging"
RECON = "network reconnaissance"
ADMIN = "remote administration"


CATALOGUE: tuple[ToolSignature, ...] = (
    # ---------------- Remote access ----------------
    ToolSignature(
        "AnyDesk", REMOTE_ACCESS,
        processes=("anydesk.exe",),
        paths=("\\anydesk\\", "\\anydesk.exe"),
        ports=(7070,),
    ),
    ToolSignature(
        "TeamViewer", REMOTE_ACCESS,
        processes=(
            "teamviewer.exe", "teamviewer_service.exe",
            "tv_w32.exe", "tv_x64.exe",
        ),
        paths=("\\teamviewer\\",),
        ports=(5938,),
    ),
    ToolSignature(
        "VNC (Tight/Ultra/Real)", REMOTE_ACCESS,
        processes=(
            "winvnc.exe", "winvnc4.exe", "vncviewer.exe",
            "tvnserver.exe", "uvnc_service.exe",
        ),
        paths=("\\tightvnc\\", "\\ultravnc\\", "\\realvnc\\"),
        ports=(5900,),
    ),
    ToolSignature(
        "ScreenConnect / ConnectWise Control", REMOTE_ACCESS,
        processes=(
            "screenconnect.clientservice.exe",
            "screenconnect.windowsclient.exe",
        ),
        paths=("\\screenconnect\\", "\\connectwisecontrol\\"),
    ),
    ToolSignature(
        "Atera Agent", REMOTE_ACCESS,
        processes=("ateraagent.exe", "agentpackagemonitoring.exe"),
        paths=("\\ateranetworks\\",),
    ),
    ToolSignature(
        "Splashtop", REMOTE_ACCESS,
        processes=("srmanager.exe", "srservice.exe", "sragent.exe"),
        paths=("\\splashtop\\",),
    ),
    ToolSignature(
        "LogMeIn", REMOTE_ACCESS,
        processes=("logmein.exe", "lmiguardiansvc.exe"),
        paths=("\\logmein\\",),
    ),
    ToolSignature(
        "DWService", REMOTE_ACCESS,
        processes=("dwagent.exe", "dwagsvc.exe"),
        paths=("\\dwagent\\",),
    ),
    ToolSignature(
        "Remote Utilities", REMOTE_ACCESS,
        processes=("rutserv.exe", "rfusclient.exe"),
        paths=("\\remoteutilities\\",),
    ),
    ToolSignature(
        "Radmin", REMOTE_ACCESS,
        processes=("rserver3.exe", "radmin.exe"),
        paths=("\\radmin\\",),
        ports=(4899,),
    ),
    ToolSignature(
        "DameWare", REMOTE_ACCESS,
        processes=("dwrcs.exe", "dwrcst.exe"),
        paths=("\\dameware\\",),
    ),
    ToolSignature(
        "Supremo", REMOTE_ACCESS,
        processes=("supremo.exe", "supremosystem.exe"),
        paths=("\\supremo\\",),
    ),
    ToolSignature(
        "Ammyy Admin", REMOTE_ACCESS,
        processes=("aa_v3.exe", "ammyy_admin.exe"),
    ),
    ToolSignature(
        "Windows Quick Assist", REMOTE_ACCESS,
        processes=("quickassist.exe",),
        builtin=True,
        note="Ships with Windows; abused for social-engineering access.",
    ),
    ToolSignature(
        "Windows Remote Assistance", REMOTE_ACCESS,
        processes=("msra.exe",),
        builtin=True,
        note="Ships with Windows.",
    ),

    # ---------------- Lateral movement ----------------
    ToolSignature(
        "PsExec (Sysinternals)", LATERAL_MOVEMENT,
        processes=("psexec.exe", "psexec64.exe", "psexesvc.exe"),
        paths=("\\psexec.exe", "\\psexesvc.exe"),
    ),
    ToolSignature(
        "PAExec", LATERAL_MOVEMENT,
        processes=("paexec.exe",),
        paths=("\\paexec.exe",),
    ),
    ToolSignature(
        "RemCom", LATERAL_MOVEMENT,
        processes=("remcom.exe", "remcomsvc.exe"),
    ),
    ToolSignature(
        "Remote Desktop client", LATERAL_MOVEMENT,
        processes=("mstsc.exe",),
        builtin=True,
        ports=(3389,),
        note="Ships with Windows; only execution is meaningful.",
    ),
    ToolSignature(
        "Windows Remote Shell / WinRM", LATERAL_MOVEMENT,
        processes=("winrs.exe", "wsmprovhost.exe"),
        builtin=True,
        note="Ships with Windows.",
    ),
    ToolSignature(
        "WMI remote execution", LATERAL_MOVEMENT,
        processes=("wmic.exe",),
        cmdline_tokens=("/node:",),
        builtin=True,
        note="Ships with Windows; the /node: switch indicates remote use.",
    ),

    # ---------------- Tunnelling ----------------
    ToolSignature(
        "ngrok", TUNNELING,
        processes=("ngrok.exe",),
        paths=("\\ngrok.exe",),
    ),
    ToolSignature(
        "chisel", TUNNELING,
        processes=("chisel.exe",),
        paths=("\\chisel.exe",),
    ),
    ToolSignature(
        "frp", TUNNELING,
        processes=("frpc.exe", "frps.exe"),
        paths=("\\frpc.ini",),
    ),
    ToolSignature(
        "PuTTY plink", TUNNELING,
        processes=("plink.exe",),
        paths=("\\plink.exe",),
    ),
    ToolSignature(
        "Netcat", TUNNELING,
        processes=("nc.exe", "nc64.exe", "ncat.exe"),
        paths=("\\nc.exe", "\\ncat.exe"),
    ),

    # ---------------- Transfer / staging ----------------
    ToolSignature(
        "Rclone", TRANSFER,
        processes=("rclone.exe",),
        paths=("\\rclone.exe", "\\rclone.conf"),
    ),
    ToolSignature(
        "WinSCP", TRANSFER,
        processes=("winscp.exe",),
        paths=("\\winscp\\", "\\winscp.exe"),
    ),
    ToolSignature(
        "FileZilla", TRANSFER,
        processes=("filezilla.exe",),
        paths=("\\filezilla\\",),
    ),
    ToolSignature(
        "MEGA sync", TRANSFER,
        processes=("megasync.exe", "megacmdserver.exe"),
        paths=("\\megasync\\",),
    ),
    ToolSignature(
        "PuTTY pscp / psftp", TRANSFER,
        processes=("pscp.exe", "psftp.exe"),
    ),
    ToolSignature(
        "7-Zip", TRANSFER,
        processes=("7z.exe", "7za.exe", "7zg.exe"),
        note="Archiver; relevant only as possible collection or staging.",
    ),
    ToolSignature(
        "WinRAR", TRANSFER,
        processes=("winrar.exe", "rar.exe"),
        paths=("\\winrar\\",),
        note="Archiver; relevant only as possible collection or staging.",
    ),

    # ---------------- Reconnaissance ----------------
    ToolSignature(
        "Nmap", RECON,
        processes=("nmap.exe", "zenmap.exe"),
        paths=("\\nmap\\", "\\nmap.exe"),
    ),
    ToolSignature(
        "Angry IP Scanner", RECON,
        processes=("ipscan.exe", "ipscan-win64.exe"),
    ),
    ToolSignature(
        "Advanced IP Scanner", RECON,
        processes=(
            "advanced_ip_scanner.exe",
            "advanced_ip_scanner_console.exe",
        ),
        paths=("\\advanced ip scanner\\",),
    ),
    ToolSignature(
        "SoftPerfect Network Scanner", RECON,
        processes=("netscan.exe",),
    ),
    ToolSignature(
        "AdFind", RECON,
        processes=("adfind.exe",),
        paths=("\\adfind.exe",),
    ),
    ToolSignature(
        "BloodHound / SharpHound", RECON,
        processes=("sharphound.exe", "bloodhound.exe"),
        paths=("\\sharphound.exe",),
    ),

    # ---------------- Remote administration ----------------
    ToolSignature(
        "PowerShell remoting", ADMIN,
        cmdline_tokens=(
            "-computername", "enter-pssession", "invoke-command",
        ),
        builtin=True,
        note="Ships with Windows.",
    ),
    ToolSignature(
        "Service control (remote)", ADMIN,
        # sc.exe is unremarkable locally, so the tool is reported only when
        # the command line names a remote host: "\\HOST\" but never the
        # local-device form "\\.\", which is how a named pipe is addressed.
        cmdline_regex=r"\bsc(?:\.exe)?\b.*\\\\(?!\.\\)[A-Za-z0-9._-]+",
        builtin=True,
        note="Ships with Windows; a UNC target indicates remote use.",
    ),
)


# ==============================================================================
# Matching
# ==============================================================================


@dataclass
class ToolMatch:
    """One tool observed in the evidence, with everything that supports it."""

    tool: ToolSignature
    strength: str
    evidence_ids: list[int] = field(default_factory=list)
    details: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.tool.name


def _process_matches(observed: str, candidate: str) -> bool:
    """
    Compare a process name against a catalogue entry.

    ``observed`` may be truncated to the width of the fixed-size EPROCESS
    field, so a shorter observed name that prefixes the candidate counts.
    """

    left = (observed or "").strip().lower()
    right = candidate.lower()

    if not left:
        return False

    if left == right:
        return True

    return len(left) >= _TRUNCATED_NAME_LENGTH and right.startswith(left)


def _rows(
    session: Session,
    investigation_id: str,
    plugin: str,
) -> list[tuple[int, dict]]:
    """Load (evidence id, decoded artifact) pairs for one completed plugin."""

    statement = (
        select(PluginResult.id, PluginResult.artifact_value)
        .select_from(MemoryDump)
        .join(PluginExecution, PluginExecution.memory_dump_id == MemoryDump.id)
        .join(
            PluginResult,
            PluginResult.plugin_execution_id == PluginExecution.id,
        )
        .where(MemoryDump.investigation_id == investigation_id)
        .where(PluginExecution.plugin_name == plugin)
        .where(PluginExecution.execution_status == "completed")
    )

    loaded: list[tuple[int, dict]] = []

    for identifier, raw in session.execute(statement).all():
        try:
            value = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict):
            loaded.append((identifier, value))

    return loaded


def match_tools(
    session: Session,
    investigation_id: str,
) -> list[ToolMatch]:
    """
    Find known tools in the evidence already collected for an investigation.

    Returns matches ordered strongest first. Built-in Windows tooling is
    included only when observed executing.
    """

    matches: dict[str, ToolMatch] = {}

    def record(
        tool: ToolSignature,
        strength: str,
        identifier: int,
        detail: str,
    ) -> None:

        existing = matches.get(tool.name)

        if existing is None:
            matches[tool.name] = ToolMatch(
                tool, strength, [identifier], [detail]
            )
            return

        if _STRENGTH_ORDER[strength] < _STRENGTH_ORDER[existing.strength]:
            existing.strength = strength

        if identifier not in existing.evidence_ids:
            existing.evidence_ids.append(identifier)

        if detail not in existing.details:
            existing.details.append(detail)

    # --- running processes -------------------------------------------------
    for plugin in ("windows.pslist", "windows.psscan"):
        for identifier, value in _rows(session, investigation_id, plugin):

            observed = str(value.get("imagefilename") or "")

            for tool in CATALOGUE:
                if any(
                    _process_matches(observed, name)
                    for name in tool.processes
                ):
                    record(
                        tool,
                        EXECUTED,
                        identifier,
                        f"process {observed} (PID {value.get('pid')}) "
                        f"via {plugin}",
                    )

    # --- command lines -----------------------------------------------------
    for identifier, value in _rows(session, investigation_id, "windows.cmdline"):

        process = str(value.get("process") or "")
        args = str(value.get("args") or "")
        lowered = args.lower()

        for tool in CATALOGUE:

            if any(
                _process_matches(process, name) for name in tool.processes
            ):
                record(
                    tool,
                    EXECUTED,
                    identifier,
                    f"command line for {process} "
                    f"(PID {value.get('pid')}): {args[:160]}",
                )
                continue

            if not args:
                continue

            matched = any(token in lowered for token in tool.cmdline_tokens)

            if not matched and tool.cmdline_regex:
                matched = bool(
                    re.search(tool.cmdline_regex, args, re.IGNORECASE)
                )

            if matched:
                record(
                    tool,
                    EXECUTED,
                    identifier,
                    f"command line of {process} "
                    f"(PID {value.get('pid')}): {args[:160]}",
                )

    # --- binaries on disk --------------------------------------------------
    for identifier, value in _rows(
        session, investigation_id, "windows.filescan"
    ):

        path = str(value.get("name") or "").lower()

        if not path:
            continue

        for tool in CATALOGUE:
            # A built-in ships with the OS; finding it on disk says nothing.
            if tool.builtin or not tool.paths:
                continue

            if any(fragment in path for fragment in tool.paths):
                record(
                    tool,
                    ON_DISK,
                    identifier,
                    f"file present: {value.get('name')}",
                )

    # --- characteristic ports ----------------------------------------------
    # Only ever raised against a tool already seen by another artifact type;
    # a bare port match names no software.
    for identifier, value in _rows(
        session, investigation_id, "windows.netscan"
    ):

        port = value.get("foreignport")

        if port is None:
            continue

        for tool in CATALOGUE:
            if tool.name in matches and port in tool.ports:
                record(
                    tool,
                    NETWORK,
                    identifier,
                    f"connection to {value.get('foreignaddr')}:{port} "
                    f"({value.get('state')})",
                )

    ordered = sorted(
        matches.values(),
        key=lambda entry: (_STRENGTH_ORDER[entry.strength], entry.tool.name),
    )

    logger.info(
        "Tool signature scan for '%s': %d tool(s) matched.",
        investigation_id,
        len(ordered),
    )

    return ordered


def format_tool_matches(matches: list[ToolMatch]) -> str:
    """Render the known-tool block that precedes the evidence in the prompt."""

    lines = ["KNOWN-TOOL SIGNATURE MATCHES"]

    if not matches:
        lines.append(
            "A deterministic scan of the collected process, command-line and "
            "file-system evidence against a catalogue of "
            f"{len(CATALOGUE)} known remote-access, lateral-movement, "
            "tunnelling, transfer and reconnaissance tools found no matches."
        )
        lines.append("")
        lines.append(
            "This scan covers named tooling only. Report that no known tool "
            "was identified, and note that renamed binaries, custom implants "
            "and tools absent from the catalogue would not be detected."
        )
        return "\n".join(lines)

    lines.append(
        "The evidence was scanned against a catalogue of known tooling. "
        "Each entry below was matched deterministically on an exact "
        "executable name or path, not by similarity."
    )
    lines.append("")

    for entry in matches:
        lines.append(f"  {entry.name} — {entry.tool.category} [{entry.strength}]")
        for detail in entry.details[:4]:
            lines.append(f"      {detail}")
        if entry.tool.note:
            lines.append(f"      note: {entry.tool.note}")

    lines.append("")
    lines.append(
        "Read these as leads, not conclusions. EXECUTED means the tool was "
        "running or had a recovered command line; ON-DISK means the binary "
        "was present, which is not evidence that it ran; NETWORK is a port "
        "association and is corroborating only. Remote-access and "
        "administration tools have legitimate uses, so do not treat a match "
        "as malicious without supporting evidence, and say which of these "
        "distinctions applies to each tool you report."
    )

    return "\n".join(lines)


__all__ = [
    "CATALOGUE",
    "EXECUTED",
    "NETWORK",
    "ON_DISK",
    "ToolMatch",
    "ToolSignature",
    "format_tool_matches",
    "match_tools",
]
