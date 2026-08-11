"""
Artifact/plugin-specific forensic indicators for the evidence classifier.

Each indicator is a deterministic matcher over a single record's normalized
attributes. Indicators are deliberately conservative:

* Weak indicators (weight 1-2) never decide a severity on their own.
* Strong indicators (weight 3) describe inherently suspicious behavior, but
  a HIGH classification still requires corroborating evidence from another
  plugin family (see ``scorer.py`` / ``correlation.py``).

Keywords are weak signals only: no indicator returns HIGH just because a
keyword appears in an artifact value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from typing import Callable

# ==============================================================================
# Indicator Definition
# ==============================================================================


@dataclass(frozen=True)
class Indicator:
    """A single deterministic forensic indicator."""

    code: str
    weight: int
    strong: bool
    artifact_types: tuple[str, ...]
    match: Callable[[dict[str, Any]], bool]
    reason_template: str


# ==============================================================================
# Attribute Helpers
# ==============================================================================


def _first(attributes: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in attributes and attributes[key] is not None:
            return attributes[key]
    return None


def _s(value: Any) -> str:
    return "" if value is None else str(value)


def _basename_lower(name: str) -> str:
    return name.replace("\\", "/").split("/")[-1].lower()


def _stem_lower(name: str) -> str:
    base = _basename_lower(name)
    if "." in base:
        return base.rsplit(".", 1)[0]
    return base


def _is_executable(name: str) -> bool:
    return name.lower().endswith((".exe", ".dll", ".bat", ".ps1", ".scr", ".pif"))


# ==============================================================================
# Path Classification
# ==============================================================================

_TRUSTED_PATH_MARKERS = (
    "c:/windows",
    "c:/program files",
    "c:/program files (x86)",
    "/windows/system32",
    "/windows/syswow64",
)

_WRITABLE_PATH_MARKERS = (
    "/temp/",
    "/tmp/",
    "/appdata/",
    "/roaming/",
    "/local/temp",
    "/local/temp/",
    "/downloads/",
    "/desktop/",
    "/programdata/",
    "/users/",
)


def _is_trusted_path(path: str) -> bool:
    """Return True when the path is a standard Windows/system location."""

    normalized = path.replace("\\", "/").lower()

    return any(marker in normalized for marker in _TRUSTED_PATH_MARKERS)


def _is_user_writable_path(path: str) -> bool:
    """
    Return True when the path resolves to a user-writable location.

    Being in a user-writable location is a weak anomaly for executables; it
    never elevates a record to HIGH by itself.
    """

    normalized = path.replace("\\", "/").lower()

    if _is_trusted_path(normalized):
        return False

    return any(marker in normalized for marker in _WRITABLE_PATH_MARKERS)


# ==============================================================================
# Content Patterns
# ==============================================================================

_REMOTE_ENDPOINT_RE = re.compile(
    r"(?i)\b(?:--?connect|--?host|--?server|nc(?:\.exe)?)\s+"
    r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\b"
)

_IP_PORT_RE = re.compile(
    r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b"
)

_ENCODING_MARKERS = (
    "-enc",
    "-e ",
    "frombase64",
    "base64",
    "certutil -urlcache",
    "iex(",
    "new-object net.webclient",
    "downloadstring",
    "-w hidden",
)

_RECON_COMMANDS = (
    "whoami",
    "net user",
    "net localgroup",
    "net group",
    "net view",
    "systeminfo",
    "tasklist",
    "query user",
    "reg query",
    "ipconfig /all",
)

_PERSISTENCE_MARKERS = (
    r"\\run\\",
    r"\\runonce\\",
    r"image file execution options",
    r"\\services\\",
    r"currentversion\\run",
)

_DISGUISE_MARKERS = (
    ".exe.",
    ".bat.",
    ".cmd.",
    ".scr.",
    ".ps1.",
)


# ==============================================================================
# Indicator Matchers (one function per indicator code)
# ==============================================================================


def _psl_01(attributes: dict[str, Any]) -> bool:
    path = _first(attributes, "path")
    name = _first(attributes, "name")
    if path is None or name is None:
        return False
    if not _is_executable(_s(name)):
        return False
    return _is_user_writable_path(_s(path))


def _psl_02(attributes: dict[str, Any]) -> bool:
    path = _first(attributes, "path")
    name = _first(attributes, "name")
    if path is None or name is None:
        return False
    base = _basename_lower(_s(path))
    name_lower = _s(name).lower()
    if not base or not name_lower:
        return False
    if "." not in base:
        # The path is a directory (e.g. C:\Windows), not a file object.
        return False
    stem = _stem_lower(_s(path))
    name_stem = _stem_lower(name_lower)
    if stem == name_stem:
        return False
    if base in name_lower or name_lower in base:
        return False
    return True


def _cmd_01(attributes: dict[str, Any]) -> bool:
    cmd = _s(_first(attributes, "cmd", "commandline", "cmd"))
    return bool(_REMOTE_ENDPOINT_RE.search(cmd) or _IP_PORT_RE.search(cmd))


def _cmd_02(attributes: dict[str, Any]) -> bool:
    cmd = _s(_first(attributes, "cmd", "commandline", "cmd")).strip().lower()
    return any(cmd.startswith(prefix) or f" {prefix}" in cmd for prefix in _RECON_COMMANDS)


def _cmd_03(attributes: dict[str, Any]) -> bool:
    cmd = _s(_first(attributes, "cmd", "commandline", "cmd")).lower()
    return any(marker in cmd for marker in _ENCODING_MARKERS)


def _cmd_04(attributes: dict[str, Any]) -> bool:
    cmd = _s(_first(attributes, "cmd", "commandline", "cmd"))
    first = cmd.split()[0] if cmd.split() else ""
    if not _is_executable(first):
        return False
    return _is_user_writable_path(first)


def _fs_01(attributes: dict[str, Any]) -> bool:
    name = _s(_first(attributes, "name", "path"))
    if not _is_executable(name):
        return False
    return _is_user_writable_path(name)


def _fs_02(attributes: dict[str, Any]) -> bool:
    name = _s(_first(attributes, "name", "path")).lower()
    return any(marker in name for marker in _DISGUISE_MARKERS)


def _ns_01(attributes: dict[str, Any]) -> bool:
    remote_ip = _s(_first(attributes, "remote_ip", "remoteip")).lower()
    if not remote_ip or remote_ip.startswith(("127.", "::1", "0.0.0.0", "::")):
        return False
    return True


def _ns_02(attributes: dict[str, Any]) -> bool:
    state = _s(_first(attributes, "state", "status")).lower()
    if "listen" not in state and "bound" not in state:
        return False
    local_port = _s(_first(attributes, "local_port", "localport"))
    try:
        return int(local_port) >= 1024
    except (TypeError, ValueError):
        return False


def _dl_01(attributes: dict[str, Any]) -> bool:
    name = _s(_first(attributes, "name", "path"))
    if not name.lower().endswith((".dll", ".exe")):
        return False
    return _is_user_writable_path(name)


def _hd_01(attributes: dict[str, Any]) -> bool:
    access = _s(_first(attributes, "granted_access", "access", "mask"))
    try:
        mask = int(access, 0)
    except (TypeError, ValueError):
        return False
    process_all_access = 0x1F0FFF
    vm_write = 0x0020
    vm_operation = 0x0008
    return bool(mask & (process_all_access | vm_write | vm_operation))


def _mf_01(attributes: dict[str, Any]) -> bool:
    # A malfind result is an injected-memory indicator by definition.
    return True


def _mf_02(attributes: dict[str, Any]) -> bool:
    protection = _s(_first(attributes, "protection", "vad_protection")).upper()
    return any(
        marker in protection
        for marker in ("PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY", "RWX", "EXECUTE_READWRITE")
    )


def _pk_01(attributes: dict[str, Any]) -> bool:
    key = _s(_first(attributes, "key", "path", "name")).lower()
    return any(re.search(pattern, key, re.IGNORECASE) for pattern in _PERSISTENCE_MARKERS)


# ==============================================================================
# Indicator Tables (artifact_type -> indicators)
# ==============================================================================

INDICATOR_TABLES: dict[str, list[Indicator]] = {
    "info": [],
    "pslist": [
        Indicator(
            code="PSL-01",
            weight=2,
            strong=False,
            artifact_types=("pslist",),
            match=_psl_01,
            reason_template="process executable in user-writable path: {path}",
        ),
        Indicator(
            code="PSL-02",
            weight=1,
            strong=False,
            artifact_types=("pslist",),
            match=_psl_02,
            reason_template="process name does not match its on-disk path: {path} vs {name}",
        ),
    ],
    "pstree": [],
    "cmdline": [
        Indicator(
            code="CMD-01",
            weight=3,
            strong=True,
            artifact_types=("cmdline",),
            match=_cmd_01,
            reason_template="command line embeds a remote endpoint: {cmd}",
        ),
        Indicator(
            code="CMD-02",
            weight=3,
            strong=True,
            artifact_types=("cmdline",),
            match=_cmd_02,
            reason_template="command line contains a recon/administration command: {cmd}",
        ),
        Indicator(
            code="CMD-03",
            weight=2,
            strong=False,
            artifact_types=("cmdline",),
            match=_cmd_03,
            reason_template="command line uses obfuscation/encoding: {cmd}",
        ),
        Indicator(
            code="CMD-04",
            weight=1,
            strong=False,
            artifact_types=("cmdline",),
            match=_cmd_04,
            reason_template="command line references an executable in a user-writable path: {cmd}",
        ),
    ],
    "filescan": [
        Indicator(
            code="FS-01",
            weight=2,
            strong=False,
            artifact_types=("filescan",),
            match=_fs_01,
            reason_template="file is an executable in a user-writable path: {name}",
        ),
        Indicator(
            code="FS-02",
            weight=1,
            strong=False,
            artifact_types=("filescan",),
            match=_fs_02,
            reason_template="file name suggests disguise: {name}",
        ),
    ],
    "netscan": [
        Indicator(
            code="NS-01",
            weight=3,
            strong=True,
            artifact_types=("netscan",),
            match=_ns_01,
            reason_template="outbound network connection to non-loopback address: {remote_ip}:{remote_port}",
        ),
        Indicator(
            code="NS-02",
            weight=2,
            strong=False,
            artifact_types=("netscan",),
            match=_ns_02,
            reason_template="listening socket on non-default port: {local_port}",
        ),
    ],
    "dlllist": [
        Indicator(
            code="DL-01",
            weight=2,
            strong=False,
            artifact_types=("dlllist",),
            match=_dl_01,
            reason_template="library loaded from a user-writable path: {name}",
        ),
    ],
    "handles": [
        Indicator(
            code="HD-01",
            weight=2,
            strong=False,
            artifact_types=("handles",),
            match=_hd_01,
            reason_template="process handle with elevated access to another process",
        ),
    ],
    "malfind": [
        Indicator(
            code="MF-01",
            weight=3,
            strong=True,
            artifact_types=("malfind",),
            match=_mf_01,
            reason_template="injected memory region detected by windows.malfind",
        ),
        Indicator(
            code="MF-02",
            weight=2,
            strong=False,
            artifact_types=("malfind",),
            match=_mf_02,
            reason_template="memory region with RWX/executable-write protection: {protection}",
        ),
    ],
    "printkey": [
        Indicator(
            code="PK-01",
            weight=2,
            strong=False,
            artifact_types=("printkey",),
            match=_pk_01,
            reason_template="registry key suggests persistence: {key}",
        ),
    ],
}


def indicators_for(artifact_type: str) -> list[Indicator]:
    """Return the indicator list for an artifact type (possibly empty)."""

    return INDICATOR_TABLES.get(artifact_type, [])


def is_supported(artifact_type: str) -> bool:
    """Return True when the artifact type has an indicator table."""

    return artifact_type in INDICATOR_TABLES
