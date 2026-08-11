"""
Canonical forensic entity extraction for cross-plugin correlation.

The normalizer stores flat, lowercased attribute dicts with plugin-specific
key names. This module maps those attributes onto a small set of canonical
entities (processes, files, connections, registry keys) so that evidence
from different plugins can be joined on the same real-world object.

Entity keys are plain tuples so they can be stored in sets/dicts.
"""

from __future__ import annotations

from typing import Any

# ==============================================================================
# Entity Helpers
# ==============================================================================


def _first(attributes: dict[str, Any], *keys: str) -> Any:
    """Return the first present, non-None value among the candidate keys."""

    for key in keys:
        if key in attributes and attributes[key] is not None:
            return attributes[key]
    return None


def normalize_pid(value: Any) -> str | None:
    """Normalize a process id to a canonical string, or None."""

    if value is None:
        return None

    if isinstance(value, int):
        return str(value)

    try:
        return str(int(str(value).strip()))
    except (TypeError, ValueError):
        return None


def _norm_path(path: Any) -> str | None:
    """Normalize a file/directory path to a lowercase canonical form."""

    if path is None:
        return None

    text = str(path).strip()

    if not text:
        return None

    return text.lower().replace("\\", "/").strip("/")


def _basename(path: str) -> str:
    """Return the final path component of a normalized path."""

    return path.split("/")[-1]


def _stem(name: str) -> str:
    """Return the lowercase basename without its final extension."""

    base = _basename(name)

    if "." in base:
        return base.rsplit(".", 1)[0]

    return base


def _as_lower(value: Any) -> str | None:
    """Lowercase a scalar value for entity matching, or None."""

    if value is None:
        return None

    text = str(value).strip().lower()

    return text or None


def _cmd_token(token: str) -> str:
    """Return the first whitespace-delimited token of a command line."""

    text = str(token).strip()

    if not text:
        return ""

    return text.split()[0]


def _looks_like_path(token: str) -> bool:
    """Return True when a token looks like a file path or executable name."""

    lowered = token.lower()

    if "/" in token or "\\" in token:
        return True

    return lowered.endswith((".exe", ".dll", ".bat", ".cmd", ".ps1", ".scr", ".pif"))


# ==============================================================================
# Entity Extraction
# ==============================================================================

PATH_TYPES = {
    "pslist",
    "cmdline",
    "filescan",
    "dlllist",
}


def extract_entities(
    artifact_type: str,
    attributes: dict[str, Any],
) -> set[tuple[Any, ...]]:
    """
    Extract canonical entity keys from one record's attributes.

    Returns a set of tuples of the form::

        ("pid", pid)
        ("name", name)
        ("path", path)
        ("path_stem", stem)
        ("conn", remote_ip, remote_port)
        ("reg", key_path)
    """

    entities: set[tuple[Any, ...]] = set()

    pid = normalize_pid(_first(attributes, "pid", "processid"))

    if pid is not None:
        entities.add(("pid", pid))

    name = _as_lower(_first(attributes, "name", "processname", "imagename"))

    if name is not None:
        entities.add(("name", name))

    # File paths ----------------------------------------------------------

    if artifact_type in PATH_TYPES:

        if artifact_type == "cmdline":
            cmd_value = _first(attributes, "cmd", "commandline")

            if cmd_value is not None:
                token = _cmd_token(cmd_value)

                if _looks_like_path(token):
                    path = _norm_path(token)

                    if path is not None:
                        entities.add(("path", path))
                        entities.add(("path_stem", _stem(path)))

                name = _as_lower(_basename(_norm_path(token) or token))

                if name:
                    entities.add(("name", name))

        else:
            path_value = _first(attributes, "path", "name")

            path = _norm_path(path_value)

            if path is not None:
                entities.add(("path", path))
                entities.add(("path_stem", _stem(path)))

    # Network connections --------------------------------------------------

    if artifact_type == "netscan":

        remote_ip = _as_lower(_first(attributes, "remote_ip", "remoteip"))
        remote_port = _first(attributes, "remote_port", "remoteport")

        if remote_ip is not None and remote_ip != "":
            entities.add(
                ("conn", remote_ip, str(remote_port).strip() if remote_port is not None else "")
            )

    # Registry keys --------------------------------------------------------

    if artifact_type in {"printkey", "registry"}:

        key_value = _first(attributes, "key", "path", "hive", "name")

        key_path = _norm_path(key_value)

        if key_path is not None:
            entities.add(("reg", key_path))

    return entities
