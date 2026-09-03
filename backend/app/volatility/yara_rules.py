"""
YARA rule loading for Volatility memory scanning.

Compiles the rule set under ``backend/rules/yara`` into a single compiled
file and hands Volatility's ``windows.vadyarascan`` a reference to it.

A compiled ruleset is used rather than passing individual ``--yara-file``
arguments because ``vadyarascan`` accepts only one rule source, and
concatenating the files at the command line is not possible. Compiling also
guarantees the scan uses exactly the rule semantics validated at build time.

Provenance and licensing for every rule live in ``rules/yara/README.md``.
"""

from __future__ import annotations

from pathlib import Path

from app.core.config import BACKEND_DIR, TEMP_DIR
from app.core.logging import get_logger

logger = get_logger(__name__)

RULES_DIR = BACKEND_DIR / "rules" / "yara"

COMPILED_RULES_PATH = TEMP_DIR / "fia_yara_rules.compiled"


def rule_files() -> list[Path]:
    """
    Return every rule file, vendor rules first then derived ones.

    Sorted for deterministic ordering so a compiled ruleset is reproducible.
    """

    files: list[Path] = []

    for subdirectory in ("vendor", "derived"):
        directory = RULES_DIR / subdirectory
        if directory.is_dir():
            files.extend(sorted(directory.glob("*.yar")))

    return files


def compile_rules(force: bool = False) -> Path:
    """
    Compile the rule set to a single file and return its path.

    Recompiles when the compiled file is missing or older than any source
    rule, so editing a rule takes effect without a manual step.

    Raises
    ------
    RuntimeError
        If no rules are present or compilation fails. Callers surface this
        as a plugin-level failure rather than aborting the investigation.
    """

    import yara  # imported lazily: only needed when YARA scanning runs

    sources = rule_files()

    if not sources:
        raise RuntimeError(
            f"No YARA rules found under {RULES_DIR}."
        )

    COMPILED_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)

    if not force and COMPILED_RULES_PATH.exists():

        compiled_at = COMPILED_RULES_PATH.stat().st_mtime

        if all(source.stat().st_mtime <= compiled_at for source in sources):
            return COMPILED_RULES_PATH

    # Namespace each file by its stem so rule origins stay distinguishable
    # in match output.
    namespaces = {source.stem: str(source) for source in sources}

    try:
        compiled = yara.compile(filepaths=namespaces)
        compiled.save(str(COMPILED_RULES_PATH))

    except Exception as exc:
        raise RuntimeError(
            f"Failed to compile YARA rules from {RULES_DIR}: {exc}"
        ) from exc

    logger.info(
        "Compiled %d YARA rule files to %s",
        len(sources),
        COMPILED_RULES_PATH,
    )

    return COMPILED_RULES_PATH


def yara_rule_arguments() -> list[str]:
    """
    Return the ``vadyarascan`` arguments pointing at the compiled rules.
    """

    return ["--yara-compiled-file", str(compile_rules())]


__all__ = [
    "COMPILED_RULES_PATH",
    "RULES_DIR",
    "compile_rules",
    "rule_files",
    "yara_rule_arguments",
]
