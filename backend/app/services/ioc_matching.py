"""
Exact-match IOC correlation over collected network evidence.

Why this exists
---------------
Q7 asks whether the host communicated with a specific malicious IP range.
Semantic retrieval cannot answer that: an embedding of "109.21.12.0/24" is not
meaningfully closer to the row containing 109.21.12.44 than to any other
network row, and a near-miss is indistinguishable from a hit. Address
membership is an exact predicate, so it is evaluated as one -- parsed with
``ipaddress`` and tested for containment, never by string similarity.

The negative answer matters as much as the positive one. On D2F9 no address
falls inside the queried range, and because ``netscan`` completed with 431
rows across 68 distinct addresses, that is a meaningful negative rather than
an absence of evidence. The block below says which of the two it is, using
the same distinction the coverage model draws elsewhere.

Indicator provenance
--------------------
Indicators come from two places, both traceable:

* the investigator's own question, when it names an address or range;
* indicator sets supplied by the department under ``backend/rules/iocs``.

Nothing is inferred. This module ships no threat-actor indicator lists,
because a fabricated indicator produces a confident answer about the wrong
thing -- and an attribution question answered from invented infrastructure is
worse than one left unanswered. Where a question needs a set that has not
been supplied, the prompt says so and the question goes unanswered.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.memory_dump import MemoryDump
from app.models.plugin_execution import PluginExecution
from app.models.plugin_result import PluginResult

logger = get_logger(__name__)

IOC_DIRECTORY = Path(__file__).resolve().parents[2] / "rules" / "iocs"

NETWORK_PLUGINS = ("windows.netscan", "windows.netstat")

# Addresses that identify no peer: a wildcard bind, an unspecified address, or
# the placeholder Volatility emits for a socket with no remote end.
_NON_PEER = {"*", "", "0.0.0.0", "::", "0.0.0.0:0", "-"}

# CIDR first so "10.1.2.0/24" is not truncated to the bare address "10.1.2.0".
_CIDR_RE = re.compile(
    r"\b(?:\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}|[0-9a-fA-F:]{2,}::?[0-9a-fA-F:]*/\d{1,3})\b"
)
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


# ==============================================================================
# Indicator sources
# ==============================================================================


@dataclass(frozen=True)
class IndicatorSet:
    """A named collection of network indicators and where it came from."""

    name: str
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    source: str = ""

    def __len__(self) -> int:
        return len(self.networks)


def parse_networks(values) -> tuple:
    """
    Parse address or CIDR strings into networks, skipping anything invalid.

    A bare address becomes a single-host network so containment is the only
    test callers need.
    """

    networks = []

    for value in values or ():
        text = str(value).strip()
        if not text:
            continue
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            logger.warning("Ignoring unparseable indicator '%s'.", text)

    return tuple(networks)


def networks_in_question(question: str) -> tuple:
    """
    Extract addresses and ranges the investigator named in the question.

    This is how Q7 is answered without hard-coding a range into the product:
    the indicator is supplied by whoever asked, and is visible in the audit
    trail as part of their question.
    """

    if not question:
        return ()

    found: list[str] = list(_CIDR_RE.findall(question))

    remainder = _CIDR_RE.sub(" ", question)
    found.extend(_IPV4_RE.findall(remainder))

    return parse_networks(found)


def load_indicator_sets(directory: Path | None = None) -> list[IndicatorSet]:
    """
    Load department-supplied indicator sets from JSON files.

    Each file holds ``{"name": ..., "source": ..., "networks": [...]}``. The
    directory is normally empty: this platform ships no indicator lists.
    """

    base = directory if directory is not None else IOC_DIRECTORY

    if not base.is_dir():
        return []

    sets: list[IndicatorSet] = []

    for path in sorted(base.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning("Could not read indicator set '%s': %s", path, exc)
            continue

        if not isinstance(payload, dict):
            logger.warning("Indicator set '%s' is not an object.", path)
            continue

        networks = parse_networks(payload.get("networks"))

        if not networks:
            continue

        sets.append(
            IndicatorSet(
                name=str(payload.get("name") or path.stem),
                networks=networks,
                source=str(payload.get("source") or path.name),
            )
        )

    return sets


# ==============================================================================
# Matching
# ==============================================================================


@dataclass
class AddressMatch:
    """One observed address falling inside an indicator network."""

    address: str
    network: str
    evidence_ids: list[int] = field(default_factory=list)
    details: list[str] = field(default_factory=list)


@dataclass
class NetworkScan:
    """The result of testing collected network evidence against indicators."""

    matches: list[AddressMatch] = field(default_factory=list)
    rows_examined: int = 0
    distinct_addresses: int = 0
    networks_tested: tuple = ()
    plugins_available: tuple[str, ...] = ()

    @property
    def searched(self) -> bool:
        """True when network evidence actually existed to test."""

        return self.rows_examined > 0

    @property
    def evidence_ids(self) -> tuple[int, ...]:
        return tuple(
            identifier
            for match in self.matches
            for identifier in match.evidence_ids
        )


def _network_rows(
    session: Session,
    investigation_id: str,
) -> tuple[list[tuple[int, str, dict]], tuple[str, ...]]:
    """Load decoded network rows and the plugins that produced them."""

    statement = (
        select(
            PluginResult.id,
            PluginExecution.plugin_name,
            PluginResult.artifact_value,
        )
        .select_from(MemoryDump)
        .join(PluginExecution, PluginExecution.memory_dump_id == MemoryDump.id)
        .join(
            PluginResult,
            PluginResult.plugin_execution_id == PluginExecution.id,
        )
        .where(MemoryDump.investigation_id == investigation_id)
        .where(PluginExecution.plugin_name.in_(NETWORK_PLUGINS))
        .where(PluginExecution.execution_status == "completed")
    )

    rows: list[tuple[int, str, dict]] = []
    plugins: set[str] = set()

    for identifier, plugin, raw in session.execute(statement).all():
        try:
            value = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict):
            rows.append((identifier, plugin, value))
            plugins.add(plugin)

    return rows, tuple(sorted(plugins))


def match_networks(
    session: Session,
    investigation_id: str,
    networks: tuple,
) -> NetworkScan:
    """
    Test every collected network address for membership in ``networks``.

    Both endpoints are examined, and the matching field is reported: a remote
    address is the peer, whereas a local one means the host itself holds an
    address in the range, which is a different finding.
    """

    rows, plugins = _network_rows(session, investigation_id)

    scan = NetworkScan(
        rows_examined=len(rows),
        networks_tested=tuple(networks),
        plugins_available=plugins,
    )

    if not rows:
        return scan

    by_address: dict[str, AddressMatch] = {}
    seen: set[str] = set()

    for identifier, plugin, value in rows:

        for field_name, role in (
            ("foreignaddr", "remote"),
            ("localaddr", "local"),
        ):

            text = str(value.get(field_name) or "").strip()

            if not text or text in _NON_PEER:
                continue

            seen.add(text)

            try:
                address = ipaddress.ip_address(text)
            except ValueError:
                continue

            for network in networks:
                if address.version != network.version:
                    continue
                if address not in network:
                    continue

                match = by_address.setdefault(
                    text, AddressMatch(text, str(network))
                )
                if identifier not in match.evidence_ids:
                    match.evidence_ids.append(identifier)

                detail = (
                    f"{role} address {text} "
                    f"port {value.get('foreignport') or value.get('localport')} "
                    f"state {value.get('state') or 'n/a'} via {plugin}"
                )
                if detail not in match.details:
                    match.details.append(detail)

    scan.matches = sorted(by_address.values(), key=lambda item: item.address)
    scan.distinct_addresses = len(seen)

    logger.info(
        "IOC network scan for '%s': %d row(s), %d distinct address(es), "
        "%d indicator network(s), %d match(es).",
        investigation_id,
        scan.rows_examined,
        scan.distinct_addresses,
        len(networks),
        len(scan.matches),
    )

    return scan


# ==============================================================================
# Prompt rendering
# ==============================================================================


def format_network_scan(scan: NetworkScan) -> str:
    """Render the IOC block that precedes the evidence in the prompt."""

    lines = ["INDICATOR CORRELATION (exact address matching)"]

    if not scan.networks_tested:
        lines.append(
            "No address or range was supplied to test. Membership was not "
            "evaluated. Do not claim any address was or was not contacted; "
            "say that no indicator was provided and name that in GAPS."
        )
        return "\n".join(lines)

    ranges = ", ".join(str(network) for network in scan.networks_tested)
    lines.append(f"Indicator ranges tested: {ranges}")

    if not scan.searched:
        lines.append("")
        lines.append(
            "No network evidence was collected for this investigation, so "
            "membership could NOT be evaluated. This is not a negative "
            "finding: state that the check could not be performed and name "
            "the missing network evidence in GAPS."
        )
        return "\n".join(lines)

    lines.append(
        f"Evidence searched: {scan.rows_examined:,} row(s) from "
        f"{', '.join(scan.plugins_available)}, "
        f"{scan.distinct_addresses} distinct address(es)."
    )
    lines.append("")

    if scan.matches:
        lines.append(f"{len(scan.matches)} address(es) fall inside the range:")
        for match in scan.matches:
            lines.append(f"  {match.address}  (in {match.network})")
            for detail in match.details[:4]:
                lines.append(f"      {detail}")
        lines.append("")
        lines.append(
            "These are exact matches, not similarities. Report the addresses "
            "and the connections carrying them, and say whether each was a "
            "remote peer or an address held by the host itself."
        )
        return "\n".join(lines)

    lines.append(
        "NO address in the collected network evidence falls inside the "
        "tested range. Every address was checked by numeric containment, not "
        "by text similarity, so this is a meaningful negative finding: the "
        "network evidence was searched and the range does not appear. Report "
        "it as such rather than as missing evidence."
    )
    lines.append(
        "Note the limit of the check: it covers connections still resident "
        "in memory at acquisition. A connection that closed and whose "
        "structures were reused earlier would not appear."
    )

    return "\n".join(lines)


def format_missing_indicator_set(actor: str) -> str:
    """
    Block for an attribution question with no supplied indicator set.

    Q12 asks about APT28. Answering it needs that group's infrastructure and
    tooling indicators, which this platform does not ship: inventing them
    would produce a confident answer about invented infrastructure.
    """

    return (
        "INDICATOR CORRELATION (exact address matching)\n"
        f"No indicator set has been supplied for {actor}.\n\n"
        "Attribution to a named threat actor requires a list of that actor's "
        "indicators -- infrastructure, tooling and behavioural signatures -- "
        "from a threat-intelligence source the investigating organisation "
        "trusts. This platform ships no such list, and none has been loaded "
        f"from the indicator directory.\n\n"
        "REQUIRED: state plainly that attribution cannot be performed without "
        f"a supplied {actor} indicator set, and name that as the gap. Do NOT "
        "attribute activity to this actor, and do NOT treat generic findings "
        "(injected memory, a YARA match, an outbound connection) as evidence "
        "of a specific group. Describe what the evidence shows on its own "
        "terms and leave attribution open."
    )


__all__ = [
    "IOC_DIRECTORY",
    "AddressMatch",
    "IndicatorSet",
    "NetworkScan",
    "format_missing_indicator_set",
    "format_network_scan",
    "load_indicator_sets",
    "match_networks",
    "networks_in_question",
    "parse_networks",
]
