"""
Corroboration checks for signature-based (YARA) findings.

Why this exists
---------------
On D2F9, 131 of 134 YARA matches fall inside ``MsMpEng.exe`` — Microsoft
Defender's antimalware service. Defender holds malware signature patterns in
its own memory, so a YARA rule written for a malware family matches Defender's
copy of that family's signature. The match is expected on a clean machine and
is not evidence of infection.

Asked to triage those matches, the model reported "the presence of XMRig
cryptocurrency mining malware" in three consecutive runs at temperature 0.0,
with ``GAPS: None.`` One earlier run did spot the false positive unprompted —
which made the behaviour look like sampling variance when it was really a
systematic failure with one lucky exception. Prompt wording alone does not
hold here, so the check is performed in code and its result is stated to the
reader whatever the model concludes.

The remaining three D2F9 matches show the second failure mode: two matched
the ASCII string ``stratum+tcp`` inside a browser process, and one matched
eleven consecutive null bytes. A rule that fires on null padding carries no
information at all, so such matches are counted separately and never treated
as corroboration.

What this module does NOT do
----------------------------
It does not decide that a finding is a false positive, and it never suppresses
a match. A real miner running on a host whose Defender also holds the XMRig
signature would still be reported — it would simply appear as a match outside
the security product, which is exactly what corroboration means here. The
check reports where the evidence sits and refuses to let an uncorroborated
match be presented as a confirmed detection.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.memory_dump import MemoryDump
from app.models.plugin_execution import PluginExecution
from app.models.plugin_result import PluginResult
from app.services.tool_signatures import process_name_matches

logger = get_logger(__name__)


# ==============================================================================
# Security products
# ==============================================================================

# Processes belonging to endpoint security products. These legitimately hold
# malware signatures, unpacked samples and quarantined content in memory, so a
# YARA hit inside one is expected rather than incriminating.
SECURITY_PROCESSES: dict[str, str] = {
    # Microsoft Defender / Defender for Endpoint
    "msmpeng.exe": "Microsoft Defender (antimalware service)",
    "mpdefendercoreservice.exe": "Microsoft Defender (core service)",
    "nissrv.exe": "Microsoft Defender (network inspection)",
    "mssense.exe": "Microsoft Defender for Endpoint (sensor)",
    "senseir.exe": "Microsoft Defender for Endpoint (response)",
    "sensecncproxy.exe": "Microsoft Defender for Endpoint (proxy)",
    "mpcmdrun.exe": "Microsoft Defender (command-line scanner)",
    "securityhealthservice.exe": "Windows Security health service",
    # CrowdStrike
    "csfalconservice.exe": "CrowdStrike Falcon",
    "csfalconcontainer.exe": "CrowdStrike Falcon",
    # SentinelOne
    "sentinelagent.exe": "SentinelOne",
    "sentinelstaticengine.exe": "SentinelOne",
    "sentinelservicehost.exe": "SentinelOne",
    # Sophos
    "savservice.exe": "Sophos",
    "sophosfilescanner.exe": "Sophos",
    "sophosfs.exe": "Sophos",
    # ESET
    "ekrn.exe": "ESET",
    "egui.exe": "ESET",
    # Kaspersky
    "avp.exe": "Kaspersky",
    "avpui.exe": "Kaspersky",
    # Malwarebytes
    "mbamservice.exe": "Malwarebytes",
    "mbam.exe": "Malwarebytes",
    # Trend Micro
    "ntrtscan.exe": "Trend Micro",
    "tmlisten.exe": "Trend Micro",
    "tmbmsrv.exe": "Trend Micro",
    # McAfee / Trellix
    "mcshield.exe": "McAfee / Trellix",
    "masvc.exe": "McAfee / Trellix",
    "mfemms.exe": "McAfee / Trellix",
    # Symantec / Broadcom
    "ccsvchst.exe": "Symantec / Broadcom",
    "smc.exe": "Symantec / Broadcom",
    # Carbon Black
    "cb.exe": "VMware Carbon Black",
    "repmgr.exe": "VMware Carbon Black",
    "repux.exe": "VMware Carbon Black",
    # Elastic / FireEye / Trellix HX / Bitdefender / Avast / AVG / Webroot
    "elastic-agent.exe": "Elastic Agent",
    "elastic-endpoint.exe": "Elastic Endpoint",
    "xagt.exe": "FireEye / Trellix HX",
    "bdservicehost.exe": "Bitdefender",
    "vsserv.exe": "Bitdefender",
    "avastsvc.exe": "Avast",
    "avgsvc.exe": "AVG",
    "wrsa.exe": "Webroot",
    # Forensic / analysis tooling that also holds sample content
    "procmon.exe": "Sysinternals Process Monitor",
    "procmon64.exe": "Sysinternals Process Monitor",
}


def security_product_for(process_name: str) -> str | None:
    """Return the security product owning a process name, or ``None``."""

    if not process_name:
        return None

    for known, product in SECURITY_PROCESSES.items():
        if process_name_matches(process_name, known):
            return product

    return None


# ==============================================================================
# Match quality
# ==============================================================================


def is_low_information(value: str) -> bool:
    """
    True when a matched byte sequence carries no distinguishing content.

    Volatility renders the match as space-separated hex. A run of identical
    bytes — most often null padding, which appears throughout any address
    space — tells us nothing about what produced it. One D2F9 match was
    eleven consecutive null bytes.
    """

    if not value:
        return True

    tokens = value.split()

    if not tokens:
        return True

    # Non-hex renderings are left to the general path rather than guessed at.
    try:
        byte_values = {int(token, 16) for token in tokens}
    except ValueError:
        return len(set(value.strip())) <= 1

    if len(tokens) < 4:
        # Too short to judge; treated as informative so nothing is discarded.
        return False

    return len(byte_values) <= 1


# ==============================================================================
# Assessment
# ==============================================================================


@dataclass
class RuleCorroboration:
    """How one YARA rule's matches are distributed across the host."""

    rule: str
    total: int = 0
    in_security_product: int = 0
    low_information: int = 0
    corroborating: int = 0
    products: set[str] = field(default_factory=set)
    corroborating_processes: set[str] = field(default_factory=set)

    @property
    def uncorroborated(self) -> bool:
        """True when nothing supports this rule outside a security product."""

        return self.corroborating == 0


@dataclass
class SignatureAssessment:
    """The corroboration picture for one investigation's YARA matches."""

    rules: list[RuleCorroboration] = field(default_factory=list)
    total_matches: int = 0

    @property
    def has_matches(self) -> bool:
        return self.total_matches > 0

    @property
    def uncorroborated_rules(self) -> list[RuleCorroboration]:
        return [rule for rule in self.rules if rule.uncorroborated]

    @property
    def all_uncorroborated(self) -> bool:
        """True when no rule has support outside a security product."""

        return bool(self.rules) and not any(
            not rule.uncorroborated for rule in self.rules
        )


def assess_signature_matches(
    session: Session,
    investigation_id: str,
) -> SignatureAssessment:
    """
    Classify every YARA match for an investigation by where it sits.

    Assessed over the whole match set rather than the retrieved sample, so the
    conclusion does not change with how many rows an answer happened to pull.
    """

    statement = (
        select(PluginResult.artifact_value)
        .select_from(MemoryDump)
        .join(PluginExecution, PluginExecution.memory_dump_id == MemoryDump.id)
        .join(
            PluginResult,
            PluginResult.plugin_execution_id == PluginExecution.id,
        )
        .where(MemoryDump.investigation_id == investigation_id)
        .where(PluginExecution.plugin_name == "windows.vadyarascan")
        .where(PluginExecution.execution_status == "completed")
    )

    by_rule: dict[str, RuleCorroboration] = {}
    total = 0

    for (raw,) in session.execute(statement).all():

        try:
            value = json.loads(raw)
        except (TypeError, ValueError):
            continue

        if not isinstance(value, dict):
            continue

        rule_name = str(value.get("rule") or "unnamed rule")
        process = str(value.get("imagefilename") or "")

        entry = by_rule.setdefault(rule_name, RuleCorroboration(rule_name))
        entry.total += 1
        total += 1

        product = security_product_for(process)

        if product is not None:
            entry.in_security_product += 1
            entry.products.add(product)
            continue

        if is_low_information(str(value.get("value") or "")):
            entry.low_information += 1
            continue

        entry.corroborating += 1
        if process:
            entry.corroborating_processes.add(process)

    assessment = SignatureAssessment(
        rules=sorted(by_rule.values(), key=lambda item: -item.total),
        total_matches=total,
    )

    logger.info(
        "Signature corroboration for '%s': %d matches across %d rule(s), "
        "%d rule(s) uncorroborated.",
        investigation_id,
        total,
        len(assessment.rules),
        len(assessment.uncorroborated_rules),
    )

    return assessment


# ==============================================================================
# Enforcement
# ==============================================================================

UNCORROBORATED_CEILING = 25
"""An uncorroborated signature match cannot support a confident detection."""

PARTIAL_CEILING = 50
"""Some named family in the answer is unconfirmed, so it cannot rate highly."""


def confidence_ceiling(assessment: SignatureAssessment) -> int | None:
    """
    Ceiling imposed by the corroboration state, or ``None``.

    Graded rather than all-or-nothing. On D2F9 a single rule has two weak
    matches outside Defender, which is enough to make ``all_uncorroborated``
    false — but the answer still names Cobalt Strike and Mimikatz, whose
    matches sit exclusively in Defender's memory. An answer covering any
    unconfirmed family must not read as confident.
    """

    if not assessment.has_matches:
        return None

    if assessment.all_uncorroborated:
        return UNCORROBORATED_CEILING

    if assessment.uncorroborated_rules:
        return PARTIAL_CEILING

    return None


def format_corroboration(assessment: SignatureAssessment) -> str:
    """Render the corroboration block that precedes the evidence."""

    lines = ["SIGNATURE CORROBORATION CHECK"]

    if not assessment.has_matches:
        lines.append("No YARA matches were recorded for this investigation.")
        return "\n".join(lines)

    lines.append(
        f"{assessment.total_matches} YARA match(es) across "
        f"{len(assessment.rules)} rule(s). Each match was classified by where "
        "it sits, because a match inside an endpoint security product is "
        "expected: such products hold malware signatures in memory, so a rule "
        "written for a family matches that product's copy of the family's "
        "signature on a perfectly clean host."
    )
    lines.append("")

    for rule in assessment.rules:
        lines.append(f"  {rule.rule}")
        lines.append(
            f"      {rule.total} match(es): "
            f"{rule.in_security_product} inside a security product, "
            f"{rule.low_information} content-free, "
            f"{rule.corroborating} corroborating"
        )
        if rule.products:
            lines.append(f"      product: {', '.join(sorted(rule.products))}")
        if rule.corroborating_processes:
            lines.append(
                "      corroborating processes: "
                f"{', '.join(sorted(rule.corroborating_processes))}"
            )

    lines.append("")

    uncorroborated = assessment.uncorroborated_rules

    if uncorroborated:
        names = ", ".join(rule.rule for rule in uncorroborated)
        lines.append(
            "REQUIRED: the following rules have NO support outside a security "
            f"product or content-free match: {names}. You must NOT report the "
            "associated malware as present, detected, or indicated. State "
            "that the matches are located inside a security product's memory, "
            "that this is the expected location for signature content, and "
            "that they are therefore unconfirmed. Name this limitation in "
            "GAPS — writing \"None.\" there is incorrect."
        )
    else:
        lines.append(
            "Matches outside security-product memory exist, so the findings "
            "are corroborated to that extent. Report where each match sits."
        )

    return "\n".join(lines)


def corroboration_notice(assessment: SignatureAssessment) -> str:
    """
    A deterministic notice appended to the answer.

    Stated by the platform, not the model. The model failed to draw this
    conclusion in three of four runs on identical evidence, so the reader is
    told regardless of what the answer above says.
    """

    uncorroborated = assessment.uncorroborated_rules

    if not assessment.has_matches or not uncorroborated:
        return ""

    products = sorted(
        {product for rule in uncorroborated for product in rule.products}
    )

    # Reported across every rule, not only the uncorroborated ones: the
    # overall proportion is the fact a reader needs first.
    hosted = sum(rule.in_security_product for rule in assessment.rules)
    empty = sum(rule.low_information for rule in assessment.rules)

    lines = [
        "",
        "---",
        "AUTOMATED CORROBORATION CHECK (generated by the platform, not the model)",
    ]

    where = f" ({', '.join(products)})" if products else ""

    lines.append(
        f"{hosted} of {assessment.total_matches} YARA matches in this "
        f"investigation sit inside the memory of endpoint security "
        f"software{where}. Such software stores malware signatures in memory, "
        "so a rule matching there is expected on a clean host and is not "
        "evidence of infection."
    )

    if empty:
        lines.append(
            f"A further {empty} match(es) consist of repeated identical bytes "
            "(such as null padding) and carry no distinguishing content."
        )

    lines.append("")
    lines.append("Rules with no corroborating match elsewhere on the host:")

    for rule in uncorroborated:
        lines.append(
            f"  - {rule.rule}: {rule.total} match(es), none corroborating"
        )

    lines.append("")
    lines.append(
        "Treat these as unconfirmed. Corroboration would mean the same family "
        "appearing outside security-product memory — for example an injected "
        "region, a matching process or command line, or a related network "
        "connection."
    )

    return "\n".join(lines)


__all__ = [
    "SECURITY_PROCESSES",
    "UNCORROBORATED_CEILING",
    "RuleCorroboration",
    "SignatureAssessment",
    "assess_signature_matches",
    "confidence_ceiling",
    "corroboration_notice",
    "format_corroboration",
    "is_low_information",
    "security_product_for",
]
