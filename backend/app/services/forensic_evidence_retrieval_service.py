"""
Forensic Evidence Retrieval Service for the AI Memory Forensic Investigation Assistant.

Deterministic, SQLite-backed evidence retrieval that acts as the *authoritative*
evidence source. ChromaDB is only an optimization / semantic layer.

Architectural rules
-------------------
* ``plugin_results`` (SQLite) is the source of truth. A zero-vector Chroma
  collection must NEVER produce a "no evidence" answer, and partial Chroma
  vectors must NEVER be trusted as the complete evidence set.
* Structured forensic questions (suspicious processes, PID, thread, process
  name, network, files, registry, command lines, DLLs, handles) are routed to
  deterministic SQLite retrieval FIRST, because that is the authoritative path.
* ``risk_level`` may be NULL on old investigations: that must not hide valid
  process evidence. Deterministic forensic indicators already present in the
  stored JSON (malfind regions, encoded PowerShell, suspicious command lines,
  executables in user-writable locations, external network connections) are
  surfaced so the model can still reason about suspicion without inventing a
  classification.
* Every query is bounded by SQL filtering plus an explicit LIMIT. Full-dump
  loads of large investigations are never performed.

The module intentionally imports NONE of the heavy RAG stack (SentenceTransformer,
ChromaDB, Ollama) so it can be unit-tested offline and does not collide with the
test-suite stubbing of ``app.services.ai_investigation_service``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Callable, Final

from sqlalchemy import Text, and_, case, func, literal_column, or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.logging import get_logger
from app.models.memory_dump import MemoryDump
from app.models.plugin_execution import PluginExecution
from app.models.plugin_result import PluginResult

logger = get_logger(__name__)

# ==============================================================================
# Constants
# ==============================================================================

FALLBACK_TOP_K: Final[int] = 6

# Maximum candidate rows pulled from SQLite for any single fallback query.
FALLBACK_QUERY_LIMIT: Final[int] = 2000

# Candidate scan cap for the deterministic suspicious-indicator pass.
DERIVE_SCAN_LIMIT: Final[int] = 1500

# Minimum mean similarity a Chroma semantic result must reach to be trusted for
# free-form questions. Below it, SQLite is consulted. unrelated vectors
# typically score ~0.38-0.50 with this model on this corpus.
SEMANTIC_QUALITY_FLOOR: Final[float] = 0.5

NO_EVIDENCE_COPY: Final[str] = (
    "No forensic evidence records are available for this investigation yet."
)

NO_MATCH_COPY: Final[str] = (
    "The answer cannot be determined from the available evidence. "
    "No matching forensic evidence records were found for this investigation."
)

# Artifact types that can carry a process/executable identity.
_PROCESS_BEARING_TYPES: Final[tuple[str, ...]] = (
    "pslist",
    "pstree",
    "cmdline",
    "dlllist",
    "handles",
    "netscan",
    "malfind",
    "info",
    "filescan",
)

_PROCESS_EVIDENCE_TYPES: Final[tuple[str, ...]] = (
    "pslist",
    "pstree",
    "cmdline",
    "malfind",
    "dlllist",
)

_GENERAL_PRIMARY_TYPES: Final[tuple[str, ...]] = (
    "pslist",
    "pstree",
    "cmdline",
    "netscan",
    "malfind",
)

_SUSPICIOUS_WORDS: Final[tuple[str, ...]] = (
    "suspicious",
    "malware",
    "malicious",
    "malfind",
    "inject",
    "injected",
    "shellcode",
    "compromised",
    "infected",
    "ransomware",
    "rootkit",
    "threat",
    "threats",
    "anomaly",
    "anomalies",
    "risky",
    "risk",
    "dangerous",
    "unknown",
    "unusual",
    "stealthy",
)

_ARTIFACT_KEYWORDS: Final[dict[str, tuple[str, ...]]] = {
    "netscan": (
        "network",
        "networking",
        "connection",
        "connections",
        "socket",
        "port",
        "ports",
        "listen",
        "listening",
        "remote",
        "tcp",
        "udp",
        "traffic",
        "connect",
        "connected",
        "ip",
    ),
    "filescan": (
        "file",
        "files",
        "deleted",
        "disk",
    ),
    "cmdline": (
        "command",
        "commands",
        "cmdline",
        "argument",
        "arguments",
        "launch",
    ),
    "dlllist": (
        "dll",
        "module",
        "modules",
        "library",
        "libraries",
    ),
    "handles": (
        "handle",
        "handles",
        "permission",
        "granted",
    ),
    "printkey": (
        "registry",
        "regkey",
        "key",
        "hive",
        "printkey",
    ),
    "malfind": (
        "shellcode",
        "vad",
        "executable memory",
    ),
}

_PROCESS_KEYWORDS: Final[tuple[str, ...]] = (
    "process",
    "processes",
    "pslist",
    "pstree",
    "running",
    "executable",
    "activity",
    "behavior",
    "behaviour",
    "did",
    "doing",
)

_PROCESS_ENRICHED_TYPES: Final[tuple[str, ...]] = (
    "pslist",
    "pstree",
    "cmdline",
    "malfind",
)

# Bare process tokens detected without requiring a ".exe" suffix.
_BARE_PROCESS_TOKENS: Final[tuple[str, ...]] = (
    "powershell",
    "cmd",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "wmiprvse",
    "explorer",
    "taskhost",
    "conhost",
    "dllhost",
    "splwow64",
    "vmtoolsd",
    "vmware",
    "mimikatz",
    "launcher",
    "malware",
    "tor",
)

# ==============================================================================
# Deterministic suspicious indicators (used when risk_level is absent/weak)
# ==============================================================================

_SUSPICIOUS_PATH_TOKENS: Final[tuple[str, ...]] = (
    "\\windows\\temp\\",
    "\\temp\\",
    "\\appdata\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\recycle.bin\\",
    "$recycle.bin",
    "\\downloads\\",
    "\\desktop\\",
    "\\tmp\\",
    "/dev/shm",
)

_CMD_SUSPICIOUS_TOKENS: Final[tuple[str, ...]] = (
    "powershell",
    "-enc ",
    "encodedcommand",
    "frombase64string",
    "downloadstring",
    "invoke-expression",
    " iex ",
    "bypass",
    "certutil",
    "-urlcache",
    "mshta",
    "regsvr32",
    "rundll32",
    "wmic",
    "bitsadmin",
    "-transfer",
    "cscript",
    "wscript",
    "netsh",
    "schtasks",
    ".ps1",
    ".vbs",
    ".bat",
    "cmd /c",
    "/c whoami",
    "-e ",
    "malware",
    "mimikatz",
)

_SUSPICIOUS_PORTS: Final[tuple[str, ...]] = (
    "1337",
    "4444",
    "5555",
    "6666",
    "6667",
    "9000",
    "9050",
    "31337",
    "12345",
)


# ==============================================================================
# Entity extraction
# ==============================================================================

_PID_PATTERN = re.compile(
    r"\b(?:pids?|process(?:es)?)\s*(?:id|number)?\s*[:=#]?\s*(\d{1,10})\b",
    re.IGNORECASE,
)

_TID_PATTERN = re.compile(
    r"\b(?:tids?|threads?)\s*(?:id|number)?\s*[:=#]?\s*(\d{1,10})\b",
    re.IGNORECASE,
)

_EXE_PATTERN = re.compile(
    r"\b([a-zA-Z0-9_\-\.]+\.exe)\b",
    re.IGNORECASE,
)

_PROCESS_NAMED_PATTERN = re.compile(
    r"\bprocess(?:es)?\s+(?:named|called)\s+[`'\"]([a-zA-Z0-9_\-\.]+)",
    re.IGNORECASE,
)


def _contains_keyword(lower: str, keyword: str) -> bool:
    """Match a keyword as a whole word to avoid substring false positives."""

    return re.search(rf"\b{re.escape(keyword)}\b", lower) is not None


@dataclass
class QueryIntent:
    """
    Structured interpretation of an investigator question.

    The retrieval service routes on the most specific entity present:
    PID, then TID, then process name(s), then suspicious intent, then
    artifact-type keywords.
    """

    pid: str | None = None

    tid: str | None = None

    process_names: list[str] = field(default_factory=list)

    suspicious: bool = False

    artifact_types: tuple[str, ...] | None = None

    @property
    def structured(self) -> bool:
        """True when the question targets a specific forensic entity/artifact."""

        return bool(
            self.pid
            or self.tid
            or self.process_names
            or self.suspicious
            or self.artifact_types
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        parts = []

        for field_name in (
            "pid",
            "tid",
            "process_names",
            "suspicious",
            "artifact_types",
        ):
            value = getattr(self, field_name)
            if value:
                parts.append(f"{field_name}={value}")

        return f"QueryIntent({', '.join(parts)})"


def _normalize_scalar(value: str) -> str:
    return str(int(value)).strip()


def _normalize_name(value: str) -> str:
    return value.strip().lower()


def detect_query_intent(question: str) -> QueryIntent:
    """
    Detect the forensic entities referenced by a question.

    Parameters
    ----------
    question : str
        Investigator question.

    Returns
    -------
    QueryIntent
    """

    intent = QueryIntent()
    lowered = question.lower()

    # 1. Explicit PID.
    pid_match = _PID_PATTERN.search(question)
    if pid_match:
        intent.pid = _normalize_scalar(pid_match.group(1))

    # 2. Explicit thread / TID.
    tid_match = _TID_PATTERN.search(question)
    if tid_match:
        intent.tid = _normalize_scalar(tid_match.group(1))

    # 3. Process / executable names.
    names: list[str] = []

    for match in _EXE_PATTERN.finditer(question):
        names.append(_normalize_name(match.group(1)))

    for match in _PROCESS_NAMED_PATTERN.finditer(question.rstrip("?.")):
        token = match.group(1)
        if token:
            names.append(_normalize_name(token))

    for token in _BARE_PROCESS_TOKENS:
        if _contains_keyword(lowered, token) and token not in names:
            names.append(token)

    intent.process_names = list(dict.fromkeys(names))

    # 4. Suspicious intent.
    intent.suspicious = any(
        _contains_keyword(lowered, word)
        for word in _SUSPICIOUS_WORDS
    )

    # 5. Artifact-type keywords.
    matched_types: set[str] = set()

    for artifact_type, keywords in _ARTIFACT_KEYWORDS.items():
        if any(
            _contains_keyword(lowered, keyword)
            for keyword in keywords
        ):
            matched_types.add(artifact_type)

    if any(
        _contains_keyword(lowered, keyword)
        for keyword in _PROCESS_KEYWORDS
    ):
        matched_types.update(_PROCESS_ENRICHED_TYPES)

    if matched_types:
        intent.artifact_types = tuple(sorted(matched_types))

    return intent


# ==============================================================================
# Evidence parsing helpers
# ==============================================================================


def _parse_attributes(artifact_value: str) -> dict | None:
    """Parse the persisted JSON value, discarding pstree ``__children``."""

    if not artifact_value:
        return None

    try:
        parsed = json.loads(artifact_value)
    except (ValueError, TypeError):
        return None

    if not isinstance(parsed, dict):
        return None

    return {
        key: value
        for key, value in parsed.items()
        if key != "__children"
    }


def _extract_identity(
    attributes: dict | None,
) -> tuple[str | None, str | None]:
    """Extract the canonical PID and process name from parsed attributes."""

    if not attributes:
        return None, None

    pid = attributes.get("pid")

    process_name = next(
        (
            attributes.get(key)
            for key in ("imagefilename", "name", "process", "owner")
            if isinstance(attributes.get(key), str)
            and attributes.get(key).strip()
        ),
        None,
    )

    if process_name and process_name.lower().endswith(
        ("\\", "/")
    ):
        process_name = process_name[:-1]

    return (
        str(pid) if pid is not None else None,
        process_name,
    )


def _derive_suspicion(
    artifact_type: str,
    attributes: dict | None,
) -> list[str]:
    """
    Compute deterministic suspicious indicators already present in the data.

    This never fabricates a risk classification; it labels evidence with the
    concrete forensic signal behind it (injected region, encoded command,
    executable in a user-writable location, external connection, ...).
    """

    if not attributes:
        return []

    flags: list[str] = []

    # malfind presence is itself an injection finding.
    if artifact_type == "malfind":
        flags.append("injected-memory-region")

    lowered_values = " ".join(
        str(value).lower()
        for value in attributes.values()
        if isinstance(value, (str, int, float))
    )

    if artifact_type == "cmdline":
        if any(token in lowered_values for token in _CMD_SUSPICIOUS_TOKENS):
            flags.append("suspicious-command")

    if artifact_type in ("pslist", "pstree", "cmdline"):
        path_or_image = " ".join(
            str(attributes.get(key) or "").lower()
            for key in ("path", "imagefilename", "name")
        )
        if any(token in path_or_image for token in _SUSPICIOUS_PATH_TOKENS):
            flags.append("executable-in-suspicious-location")

    if artifact_type == "dlllist":
        module = str(attributes.get("name") or "").lower()
        if any(token in module for token in _SUSPICIOUS_PATH_TOKENS):
            flags.append("module-in-suspicious-location")

    if artifact_type == "netscan":
        foreign_addr = str(attributes.get("foreignaddr") or "")
        foreign_port = str(attributes.get("foreignport") or "").strip()
        if foreign_addr and foreign_addr not in (
            "0.0.0.0",
            "::",
            "127.0.0.1",
            "localhost",
        ):
            flags.append("external-network-connection")
        if foreign_port in _SUSPICIOUS_PORTS:
            flags.append(f"connection-to-port-{foreign_port}")

    return flags


# ==============================================================================
# Evidence document building
# ==============================================================================


def build_evidence_document(
    plugin_name: str,
    artifact_type: str,
    artifact_value: str,
    risk_level: str | None = None,
    suspicious_flags: list[str] | None = None,
) -> str:
    """
    Build a readable, flattened evidence block for the LLM context.

    Mirrors the indexing shape (plugin, type, attributes) but expands the
    persisted JSON so the model can read PIDs, process names, connection state,
    and registry paths directly. Risk classification and the deterministic
    suspicious indicators behind a record are included when available.
    """

    lines: list[str] = [
        f"plugin: {plugin_name}",
        f"artifact_type: {artifact_type}",
    ]

    if risk_level:
        lines.append(f"risk_level: {risk_level}")

    if suspicious_flags:
        lines.append(
            "suspicious_indicators: "
            + ", ".join(str(flag) for flag in suspicious_flags)
        )

    attributes = _parse_attributes(artifact_value)

    if attributes:
        for key, value in attributes.items():
            if value is None:
                continue
            if isinstance(value, (dict, list)):
                rendered = json.dumps(value, default=str)
            else:
                rendered = str(value)
            lines.append(f"{key}: {rendered}")

    return "\n".join(lines)


# ==============================================================================
# Retrieval service
# ==============================================================================


class ForensicEvidenceRetrievalService:
    """
    Deterministic retrieval of forensic evidence directly from SQLite.

    Every query is bounded by SQL filtering plus an explicit LIMIT. The SQLite
    JSON1 ``json_extract`` function is used for exact numeric entity matching
    (PIDs, thread IDs) so substring collisions cannot produce fake matches.
    """

    # ------------------------------------------------------------------
    # Retrieval entry point
    # ------------------------------------------------------------------

    def retrieve(
        self,
        session: Session,
        investigation_id: str,
        question: str,
        top_k: int = FALLBACK_TOP_K,
    ) -> list[dict]:
        """
        Retrieve the most relevant evidence records for a question.

        Parameters
        ----------
        session : Session

        investigation_id : str

        question : str

        top_k : int

        Returns
        -------
        list[dict]
            Matches with ``id``, ``document``, ``metadata``, and ``score``.
        """

        limit = max(1, min(int(top_k), FALLBACK_QUERY_LIMIT))

        intent = detect_query_intent(question)

        records: list[PluginResult]

        if intent.pid:
            records = self._fetch_pid(
                session, investigation_id, intent.pid, limit
            )
        elif intent.tid:
            records = self._fetch_tid(
                session, investigation_id, intent.tid, limit
            )
        elif intent.process_names:
            records = self._fetch_process_names(
                session, investigation_id, intent.process_names, limit
            )
        elif intent.suspicious:
            records = self._fetch_suspicious(
                session, investigation_id, limit
            )
            # No classified or indicator-supported records at all: fall back
            # to a grounded sample so valid evidence is never reported missing.
            if not records:
                records = self._fetch_general(
                    session, investigation_id, limit
                )
        elif intent.artifact_types:
            records = self._fetch_artifact_types(
                session, investigation_id, intent.artifact_types, limit
            )
        else:
            records = self._fetch_general(
                session, investigation_id, limit
            )

        logger.info(
            "[CHAT] SQLite entity '%s' matched %d records for '%s'.",
            intent,
            len(records),
            investigation_id,
        )

        return [
            self._to_match(record, investigation_id)
            for record in records[:top_k]
        ]

    # ------------------------------------------------------------------
    # SQL builders
    # ------------------------------------------------------------------

    @staticmethod
    def _scoped_select(
        session: Session,
        investigation_id: str,
    ):
        return (
            select(PluginResult)
            .options(
                selectinload(PluginResult.plugin_execution)
            )
            .join(
                PluginExecution,
                PluginResult.plugin_execution_id == PluginExecution.id,
            )
            .join(
                MemoryDump,
                PluginExecution.memory_dump_id == MemoryDump.id,
            )
            .where(
                MemoryDump.investigation_id == investigation_id
            )
        )

    @staticmethod
    def _json_text(path: str):
        """
        Render the guarded JSON text expression that exactly matches the
        retrieval expression indexes.

        ``CASE WHEN json_valid(...) THEN json_extract(...) END`` is used for
        two reasons: free-text artifact rows never raise ``malformed JSON``,
        and an expression index (``ix_plugin_results_json_*``) only serves a
        query when the WHERE expression textually matches the index
        expression. The JSON path must therefore be a literal rather than a
        bind parameter.
        """

        return func.cast(
            case(
                (
                    func.json_valid(PluginResult.artifact_value),
                    func.json_extract(
                        PluginResult.artifact_value,
                        literal_column(f"'{path}'"),
                    ),
                ),
                else_=None,
            ),
            Text,
        )

    @staticmethod
    def _json_valid():
        """
        SQLite ``json_valid`` guard.

        Some artifact types (``info``, ``printkey``, ...) persist free text
        rather than JSON. ``json_extract`` raises ``malformed JSON`` on such
        rows, so every JSON-path predicate must be guarded by
        ``json_valid(artifact_value)``.
        """

        return func.json_valid(PluginResult.artifact_value)

    @staticmethod
    def _scope_exists(investigation_id: str):
        """
        Correlated ``EXISTS`` investigation-scope check.

        The exact-entity queries keep ``plugin_results`` as the driving table
        so the retrieval expression indexes serve the OR predicates via
        ``MULTI-INDEX OR``; the JOIN form instead drives from ``memory_dumps``
        and scans every row of the investigation. The row set is identical.
        """

        return (
            select(1)
            .select_from(PluginExecution)
            .join(
                MemoryDump,
                PluginExecution.memory_dump_id == MemoryDump.id,
            )
            .where(PluginExecution.id == PluginResult.plugin_execution_id)
            .where(MemoryDump.investigation_id == investigation_id)
        ).exists()

    def _fetch_pid(
        self,
        session: Session,
        investigation_id: str,
        pid: str,
        limit: int,
    ) -> list[PluginResult]:
        """Fetch records whose PID exactly matches the requested value."""

        condition = or_(
            self._json_text("$.pid") == pid,
            self._json_text("$.processid") == pid,
        )

        statement = (
            select(PluginResult)
            .options(selectinload(PluginResult.plugin_execution))
            .where(self._json_valid())
            .where(condition)
            .where(self._scope_exists(investigation_id))
            .order_by(PluginResult.id.asc())
            .limit(limit)
        )

        return list(session.scalars(statement).all())

    def _fetch_tid(
        self,
        session: Session,
        investigation_id: str,
        tid: str,
        limit: int,
    ) -> list[PluginResult]:
        """Fetch thread records (thread ID keys plus Thread object handles)."""

        thread_handle = and_(
            func.lower(self._json_text("$.type")) == "thread",
            self._json_text("$.handlevalue") == tid,
        )

        condition = or_(
            self._json_text("$.tid") == tid,
            self._json_text("$.threadid") == tid,
            self._json_text("$.thread") == tid,
            thread_handle,
        )

        statement = (
            select(PluginResult)
            .options(selectinload(PluginResult.plugin_execution))
            .where(self._json_valid())
            .where(condition)
            .where(self._scope_exists(investigation_id))
            .order_by(PluginResult.id.asc())
            .limit(limit)
        )

        return list(session.scalars(statement).all())

    def _fetch_process_names(
        self,
        session: Session,
        investigation_id: str,
        names: list[str],
        limit: int,
    ) -> list[PluginResult]:
        """
        Fetch process-bearing records matching a process/executable name.

        Precise JSON field matching (imagefilename / process / owner / name)
        is served by the retrieval expression indexes; a broad whole-record
        ``LIKE`` fallback covers path values. The two bounded result sets are
        merged on ``id`` and re-ordered, which reproduces the previous single
        OR-query result exactly without forcing a full scan for every lookup.
        """

        lowered_value = func.lower(PluginResult.artifact_value)

        exact_conditions: list = []

        like_conditions: list = []

        for name in names:
            escaped = name.replace("%", r"\%").replace("_", r"\_")
            exact_conditions.extend(
                [
                    func.lower(self._json_text("$.imagefilename")) == name,
                    func.lower(self._json_text("$.process")) == name,
                    func.lower(self._json_text("$.owner")) == name,
                    func.lower(self._json_text("$.name")) == name,
                ]
            )
            like_conditions.append(
                lowered_value.like(
                    f"%{escaped}%",
                    escape="\\",
                )
            )

        base = self._scoped_select(session, investigation_id).where(
            PluginResult.artifact_type.in_(_PROCESS_BEARING_TYPES)
        )

        exact_statement = (
            select(PluginResult)
            .options(selectinload(PluginResult.plugin_execution))
            .where(
                PluginResult.artifact_type.in_(_PROCESS_BEARING_TYPES),
                self._json_valid(),
                or_(*exact_conditions),
                self._scope_exists(investigation_id),
            )
            .order_by(PluginResult.id.asc())
            .limit(limit)
        )
        exact = list(session.scalars(exact_statement).all())

        like_statement = (
            base.where(self._json_valid())
            .where(or_(*like_conditions))
            .order_by(PluginResult.id.asc())
            .limit(limit)
        )
        like = list(session.scalars(like_statement).all())

        merged: dict[int, PluginResult] = {}

        for record in exact + like:
            merged.setdefault(record.id, record)

        ordered = [merged[record_id] for record_id in sorted(merged)]

        return ordered[:limit]

    def _fetch_suspicious(
        self,
        session: Session,
        investigation_id: str,
        limit: int,
    ) -> list[PluginResult]:
        """
        Fetch process/network evidence that is suspect on evidence, not on
        ``risk_level`` alone.

        1. Explicitly classified HIGH/MEDIUM records (persisted ``risk_level``).
        2. Records with deterministic suspicious indicators already present in
           their JSON (malfind regions, encoded commands, executables in
           user-writable locations, ...), even when ``risk_level`` is NULL.

        Explicit HIGH/MEDIUM ranks above indicator-derived records; process
        evidence ranks above network context.
        """

        process_types = _PROCESS_EVIDENCE_TYPES

        # 1) Explicitly classified suspicious records (all relevant types).
        risk_rank = case(
            (PluginResult.risk_level == "high", 0),
            (PluginResult.risk_level == "medium", 1),
            else_=2,
        )
        explicit_statement = (
            self._scoped_select(session, investigation_id)
            .where(
                PluginResult.artifact_type.in_(
                    process_types + ("netscan",)
                ),
                PluginResult.risk_level.in_(("high", "medium")),
            )
            .order_by(risk_rank, PluginResult.id.asc())
            .limit(max(limit, FALLBACK_QUERY_LIMIT))
        )
        explicit = list(session.scalars(explicit_statement).all())

        # 2) Deterministic indicator scan over process-bearing records.
        token_conditions = [
            func.lower(PluginResult.artifact_value).like(
                f"%{re.escape(token)}%"
            )
            for token in (
                _CMD_SUSPICIOUS_TOKENS
                + _SUSPICIOUS_PATH_TOKENS
                + (r"\.dll",)
            )
        ]

        derived_statement = (
            self._scoped_select(session, investigation_id)
            .where(
                PluginResult.artifact_type.in_(process_types),
                or_(
                    PluginResult.artifact_type == "malfind",
                    *token_conditions,
                ),
            )
            .order_by(PluginResult.id.asc())
            .limit(DERIVE_SCAN_LIMIT)
        )
        candidates = list(session.scalars(derived_statement).all())

        derived: list[PluginResult] = []

        for record in candidates:
            attributes = _parse_attributes(record.artifact_value)
            if _derive_suspicion(record.artifact_type, attributes):
                derived.append(record)

        # Merge, keeping explicit classification before derived indicators.
        merged: dict[int, PluginResult] = {}

        for record in explicit + derived:
            merged.setdefault(record.id, record)

        def _rank(record: PluginResult) -> tuple:
            type_rank = (
                0
                if record.artifact_type
                in ("pslist", "pstree", "cmdline", "malfind")
                else (
                    1 if record.artifact_type == "dlllist" else 2
                )
            )
            risk = (
                0
                if record.risk_level == "high"
                else (1 if record.risk_level == "medium" else 2)
            )
            return (type_rank, risk, record.id)

        ordered = sorted(merged.values(), key=_rank)

        logger.info(
            "[CHAT] suspicious pass: %d explicit, %d derived, %d merged.",
            len(explicit),
            len(derived),
            len(ordered),
        )

        return ordered[:limit]

    def _fetch_artifact_types(
        self,
        session: Session,
        investigation_id: str,
        artifact_types: tuple[str, ...],
        limit: int,
    ) -> list[PluginResult]:
        """Fetch evidence restricted to the routed artifact types."""

        statement = (
            self._scoped_select(session, investigation_id)
            .where(
                PluginResult.artifact_type.in_(artifact_types)
            )
            .order_by(PluginResult.id.asc())
            .limit(limit)
        )

        return list(session.scalars(statement).all())

    def _fetch_general(
        self,
        session: Session,
        investigation_id: str,
        limit: int,
    ) -> list[PluginResult]:
        """
        Fetch a representative, bounded sample for generic questions.

        Prioritizes process/command/network/injection artifacts, then fills
        the remainder from other artifact types.
        """

        primary = (
            self._scoped_select(session, investigation_id)
            .where(
                PluginResult.artifact_type.in_(_GENERAL_PRIMARY_TYPES)
            )
            .order_by(PluginResult.id.asc())
            .limit(limit)
        )

        records = list(session.scalars(primary).all())

        if len(records) < limit:
            remainder = limit - len(records)

            secondary = (
                self._scoped_select(session, investigation_id)
                .where(
                    ~PluginResult.artifact_type.in_(_GENERAL_PRIMARY_TYPES)
                )
                .order_by(PluginResult.id.asc())
                .limit(remainder)
            )

            records.extend(
                session.scalars(secondary).all()
            )

        return records

    # ------------------------------------------------------------------
    # Match shaping
    # ------------------------------------------------------------------

    def _to_match(
        self,
        record: PluginResult,
        investigation_id: str,
    ) -> dict:
        """Convert a PluginResult into a structured retriever match."""

        plugin_name = (
            record.plugin_execution.plugin_name
            if record.plugin_execution is not None
            else record.artifact_name
        )

        attributes = _parse_attributes(record.artifact_value)
        pid, process_name = _extract_identity(attributes)

        derived_flags = _derive_suspicion(
            record.artifact_type,
            attributes,
        )

        persisted_indicators: list[str] = []
        if record.risk_indicators:
            try:
                parsed_flags = json.loads(record.risk_indicators)
                if isinstance(parsed_flags, list):
                    persisted_indicators = [
                        str(flag) for flag in parsed_flags
                    ]
            except (ValueError, TypeError):
                persisted_indicators = []

        suspicious_flags = list(persisted_indicators) + derived_flags
        suspicious_flags = list(dict.fromkeys(suspicious_flags))

        document = build_evidence_document(
            plugin_name,
            record.artifact_type,
            record.artifact_value,
            risk_level=record.risk_level,
            suspicious_flags=suspicious_flags or None,
        )

        confidence = (
            record.confidence_score
            if record.confidence_score is not None
            else 0
        )

        return {
            "id": f"ev-{record.id}",
            "document": document,
            "metadata": {
                "investigation_id": investigation_id,
                "plugin_name": plugin_name,
                "artifact_type": record.artifact_type,
                "evidence_id": record.id,
                "confidence_score": record.confidence_score,
                "risk_level": record.risk_level,
                "pid": pid,
                "process_name": process_name,
                "suspicious_flags": suspicious_flags,
            },
            "distance": None,
            "score": (
                round(confidence / 100.0, 4)
                if confidence
                else None
            ),
        }


# ==============================================================================
# Reference / answer helpers (shared by semantic and fallback paths)
# ==============================================================================


def build_references(
    matches: list[dict],
    exact_match: bool = False,
) -> list[dict]:
    """Convert ranked retrieval matches into evidence references."""

    references: list[dict] = []

    for index, match in enumerate(matches):
        metadata = match.get("metadata") or {}

        references.append({
            "index": index + 1,
            "evidence_id": metadata.get("evidence_id"),
            "plugin_name": metadata.get("plugin_name"),
            "artifact_type": metadata.get("artifact_type"),
            "confidence_score": metadata.get("confidence_score"),
            "document": match.get("document", ""),
            "score": match.get("score"),
            "risk_level": metadata.get("risk_level"),
            "pid": metadata.get("pid"),
            "process_name": metadata.get("process_name"),
            "suspicious_flags": metadata.get("suspicious_flags"),
            "exact_match": exact_match,
        })

    return references


def retrieval_confidence(
    references: list[dict],
) -> int:
    """Derive a raw confidence value from the retrieved evidence scores."""

    scores = [
        reference["score"]
        for reference in references
        if reference["score"] is not None
    ]

    if not scores:
        return 0

    return max(
        0,
        min(100, int(round(max(scores) * 100))),
    )


def compute_evidence_confidence(
    references: list[dict],
    quality: str = "default",
) -> int:
    """
    Compute an evidence-quality confidence score.

    Confidence reflects evidence substance, not the LLM's self-assessment:

    * exact entity match (PID / process name) raises confidence;
    * persisted HIGH>MEDIUM classifications add weight;
    * deterministic suspicious indicators corroborate;
    * multiple corroborating process identities add weight;
    * weak semantic or generic samples are capped.
    """

    if not references:
        return 0

    base = retrieval_confidence(references)

    has_high = any(
        reference.get("risk_level") == "high"
        for reference in references
    )
    has_medium = any(
        reference.get("risk_level") == "medium"
        for reference in references
    )
    has_derived = any(
        reference.get("suspicious_flags")
        for reference in references
    )
    has_exact = any(
        reference.get("exact_match")
        for reference in references
    )

    pids = {
        reference.get("pid")
        for reference in references
        if reference.get("pid") is not None
    }
    corroborated = len(pids) >= 2 or len(references) >= 1 and (
        len(references) >= 2
    )

    confidence = base

    if has_high:
        confidence += 25
    elif has_medium:
        confidence += 15

    if has_derived:
        confidence += 10

    if has_exact:
        confidence += 15

    if corroborated:
        confidence += 5

    if quality == "structured":
        confidence = max(confidence, 60)
    elif quality == "general":
        confidence = min(confidence, 75)
    elif quality == "semantic":
        confidence = min(confidence, 65)

    return max(0, min(100, int(round(confidence))))


# ==============================================================================
# Answer generation
# ==============================================================================


def generate_answer_from_references(
    question: str,
    references: list[dict],
    llm_generate: Callable[[str], str],
    prompt_builder,
    response_parser,
    quality: str = "default",
    confidence: int | None = None,
) -> dict:
    """
    Build context, query the LLM, and parse the evidence-backed answer.

    The confidence value is derived from evidence quality, never from the
    model's own ``CONFIDENCE:`` line.

    Returns the full answer dict consumed by the chat route.
    """

    evidence_lines = [
        f"[{reference['index']}] {reference['document']}"
        for reference in references
    ]

    context = "\n\n".join(evidence_lines)

    prompt = prompt_builder.build_answer_prompt(
        question=question,
        context=context,
    )

    raw_answer = llm_generate(prompt)

    parsed = response_parser.parse_answer(
        raw_answer,
        len(references),
    )

    citations = [
        number
        for number in parsed["citations"]
        if 1 <= number <= len(references)
    ]

    citation_references = [
        references[number - 1]
        for number in citations
    ]

    if confidence is None:
        confidence = compute_evidence_confidence(
            references,
            quality=quality,
        )

    insufficient = (
        "cannot be determined from the available evidence"
        in (parsed["answer"] or "").lower()
    )

    logger.info(
        "[CHAT] answer produced with %d citations, confidence %d.",
        len(citation_references),
        confidence,
    )

    return {
        "question": question,
        "answer": parsed["answer"],
        "confidence": confidence,
        "insufficient": insufficient,
        "citations": citation_references,
        "references": references,
    }


# ==============================================================================
# Orchestrator
# ==============================================================================


def _semantic_quality(
    semantic_matches: list[dict],
) -> float:
    """Return the best similarity score among the semantic matches."""

    scores = [
        float(match.get("score") or 0.0)
        for match in semantic_matches
        if match.get("score") is not None
    ]

    return max(scores) if scores else 0.0


def answer_with_evidence_fallback(
    *,
    investigation_id: str,
    question: str,
    top_k: int,
    db: Session,
    semantic_search: Callable[[str, int], list[dict]],
    count_evidence: Callable[[], int],
    fallback_retrieve: Callable[[str, int], list[dict]],
    llm_generate: Callable[[str], str],
    prompt_builder,
    response_parser,
    lazy_index: Callable[[], None],
) -> dict:
    """
    Produce an evidence-backed answer with SQLite as the authoritative source.

    Flow
    ----
    1. Structured forensic question (suspicious, PID, process name, network,
       files, ...): retrieve deterministically from SQLite FIRST. Chroma is not
       trusted as the complete evidence set.
    2. Free-form question with strong Chroma results: answer from Chroma.
    3. Weak, empty, or failing Chroma: answer from SQLite.
    4. Lazy indexing is only ever triggered in the background after an answer
       exists — it never blocks the current question.
    """

    logger.info(
        "[CHAT] answering investigation=%s top_k=%d",
        investigation_id,
        top_k,
    )

    intent = detect_query_intent(question)

    logger.info(
        "[CHAT] investigation=%s intent=%s",
        investigation_id,
        intent,
    )

    if intent.structured:
        matches = list(fallback_retrieve(question, top_k) or [])

        if matches:
            logger.info(
                "[CHAT] investigation=%s sqlite_evidence_returned=%d "
                "(structured path)",
                investigation_id,
                len(matches),
            )
            _trigger_lazy(lazy_index, investigation_id)

            return generate_answer_from_references(
                question,
                build_references(matches, exact_match=True),
                llm_generate,
                prompt_builder,
                response_parser,
                quality="structured",
            )

        evidence_count = int(count_evidence())

        if evidence_count <= 0:
            logger.info(
                "[CHAT] investigation=%s sqlite_evidence=0 -> no evidence",
                investigation_id,
            )
            return _no_evidence_response(question)

        logger.info(
            "[CHAT] investigation=%s sqlite_evidence=%d but no entity match",
            investigation_id,
            evidence_count,
        )
        return _no_match_response(question)

    # ---- Free-form question: try Chroma, fall back to SQLite -------------

    semantic_matches: list[dict] = []

    try:
        semantic_matches = list(semantic_search(question, top_k) or [])
    except Exception as exc:
        logger.warning(
            "[CHAT] semantic retrieval failed for investigation '%s': %s",
            investigation_id,
            exc,
        )
        semantic_matches = []

    chroma_score = _semantic_quality(semantic_matches)

    logger.info(
        "[CHAT] investigation=%s chroma_documents=%d chroma_best_score=%s",
        investigation_id,
        len(semantic_matches),
        f"{chroma_score:.3f}",
    )

    if semantic_matches and chroma_score >= SEMANTIC_QUALITY_FLOOR:
        logger.info(
            "[CHAT] investigation=%s answering from Chroma (quality %.3f).",
            investigation_id,
            chroma_score,
        )
        return generate_answer_from_references(
            question,
            build_references(semantic_matches),
            llm_generate,
            prompt_builder,
            response_parser,
            quality="semantic",
        )

    matches = list(fallback_retrieve(question, top_k) or [])

    if matches:
        logger.info(
            "[CHAT] investigation=%s sqlite_evidence_returned=%d "
            "(fallback path)",
            investigation_id,
            len(matches),
        )
        _trigger_lazy(lazy_index, investigation_id)

        return generate_answer_from_references(
            question,
            build_references(matches, exact_match=False),
            llm_generate,
            prompt_builder,
            response_parser,
            quality="general",
        )

    evidence_count = int(count_evidence())

    if evidence_count <= 0:
        return _no_evidence_response(question)

    return _no_match_response(question)


def _trigger_lazy(
    lazy_index: Callable[[], None],
    investigation_id: str,
) -> None:
    """Safely kick off the one-shot background indexing job."""

    try:
        lazy_index()
    except Exception as exc:
        logger.warning(
            "[CHAT] lazy indexing failed for investigation '%s': %s",
            investigation_id,
            exc,
        )


def _no_evidence_response(question: str) -> dict:
    return {
        "question": question,
        "answer": NO_EVIDENCE_COPY,
        "confidence": 0,
        "insufficient": True,
        "citations": [],
        "references": [],
    }


def _no_match_response(question: str) -> dict:
    return {
        "question": question,
        "answer": NO_MATCH_COPY,
        "confidence": 0,
        "insufficient": True,
        "citations": [],
        "references": [],
    }


# ==============================================================================
# Singleton Instance
# ==============================================================================

forensic_evidence_retrieval_service = ForensicEvidenceRetrievalService()


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "ForensicEvidenceRetrievalService",
    "forensic_evidence_retrieval_service",
    "QueryIntent",
    "detect_query_intent",
    "_derive_suspicion",
    "build_evidence_document",
    "build_references",
    "retrieval_confidence",
    "compute_evidence_confidence",
    "generate_answer_from_references",
    "answer_with_evidence_fallback",
    "NO_EVIDENCE_COPY",
    "NO_MATCH_COPY",
    "SEMANTIC_QUALITY_FLOOR",
    "FALLBACK_TOP_K",
]