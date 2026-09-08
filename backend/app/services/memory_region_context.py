"""
Memory-region qualification for malfind evidence.

Why this exists
---------------
The evidence classifier's malfind rule matches unconditionally -- "a malfind
result is an injected-memory indicator by definition" -- so every malfind row
is stored as high severity and the count is simply the number of rows the
plugin returned. On D2F9 that is 8,912 rows across 33 processes, of which
8,856 describe *mapped* memory and the largest holders are signed Dell, Intel
and Microsoft software.

That distinction is the whole finding. Injected code is characteristically
private and committed: the attacker allocates it in the target process.
Mapped RWX memory is what a just-in-time compiler produces in ordinary
operation, which is why .NET-hosting processes are full of it. Only 56 of the
8,912 regions are private and committed.

Stating this in the prompt was not enough. Told plainly that 8,856 of 8,912
regions were mapped, the model still reported LicenseServer (PID 5572) --
``privatememory: 0``, a mapped region -- as "potential malicious code
injection". That is the same failure as the YARA matches inside Defender:
guidance in the preamble loses to a row labelled high severity. So the
qualification is attached to the row itself at the point it is rendered as
evidence, and a ceiling is enforced in code afterwards.

Nothing is reclassified or suppressed. Stored severities are untouched, every
row remains retrievable, and a private committed region is still reported as
the lead it is. What changes is that a cited region now carries its own
memory type, and an answer resting only on mapped regions cannot read as a
confident detection.
"""

from __future__ import annotations

from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)


MAPPED = "MAPPED"
PRIVATE = "PRIVATE-COMMITTED"

# Written into the rendered evidence block, and read back when the ceiling is
# applied. Keeping one source of truth avoids the annotation and the ceiling
# disagreeing about what a row is.
MAPPED_MARKER = "memory_region_type: MAPPED"
PRIVATE_MARKER = "memory_region_type: PRIVATE-COMMITTED"

MAPPED_ONLY_CEILING = 40
"""An answer resting only on JIT-typical regions is not a confident detection."""

_MALFIND_TYPES = ("malfind",)


def region_kind(attributes: dict[str, Any] | None) -> str | None:
    """
    Classify a malfind region as private-committed or mapped.

    Returns ``None`` when the record does not carry the field, so an
    unqualifiable row is never given a qualification it has not earned.
    """

    if not attributes:
        return None

    if "privatememory" not in attributes:
        return None

    value = str(attributes.get("privatememory")).strip().lower()

    if value in ("1", "true", "yes"):
        return PRIVATE

    if value in ("0", "false", "no"):
        return MAPPED

    return None


def annotate_region(
    artifact_type: str,
    attributes: dict[str, Any] | None,
) -> list[str]:
    """
    Lines to append to a rendered malfind evidence block.

    Returns an empty list for every other artifact type, and for malfind rows
    whose memory type cannot be determined.
    """

    if (artifact_type or "").lower() not in _MALFIND_TYPES:
        return []

    kind = region_kind(attributes)

    if kind is None:
        return []

    if kind == MAPPED:
        return [
            MAPPED_MARKER,
            "memory_region_note: this region is MAPPED, not private "
            "committed memory. Injected code is characteristically private "
            "and committed; mapped executable regions are what a "
            "just-in-time compiler produces in normal operation, which is "
            "why managed-code processes contain many of them. The "
            "high risk_level above is assigned to every malfind row by rule "
            "and does not reflect this distinction. Do NOT describe this "
            "region as injected, injection, or malicious on its own; report "
            "it as an executable mapped region and say that corroboration "
            "would be required.",
        ]

    return [
        PRIVATE_MARKER,
        "memory_region_note: this region is PRIVATE and COMMITTED, the shape "
        "injected code takes, and is worth examining. Note that JIT runtimes "
        "and antivirus engines also allocate private executable memory, so "
        "corroboration is still required before calling it malicious.",
    ]


def malfind_ceiling(cited_references: list[dict]) -> int | None:
    """
    Confidence ceiling implied by the malfind regions an answer cited.

    Fires only when malfind rows were actually cited and every one of them is
    mapped. A single cited private committed region lifts the ceiling, because
    the answer then rests on something that genuinely warrants attention.
    """

    mapped = 0
    private = 0

    for reference in cited_references or ():

        document = str(reference.get("document") or "")

        if PRIVATE_MARKER in document:
            private += 1
        elif MAPPED_MARKER in document:
            mapped += 1

    if private or not mapped:
        return None

    logger.info(
        "[CHAT] %d cited malfind region(s), all mapped: capping confidence "
        "at %d.",
        mapped,
        MAPPED_ONLY_CEILING,
    )

    return MAPPED_ONLY_CEILING


__all__ = [
    "MAPPED",
    "MAPPED_MARKER",
    "MAPPED_ONLY_CEILING",
    "PRIVATE",
    "PRIVATE_MARKER",
    "annotate_region",
    "malfind_ceiling",
    "region_kind",
]
