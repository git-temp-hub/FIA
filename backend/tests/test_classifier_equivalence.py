"""
Regression tests proving the optimized (indexed) correlation produces
exactly the same forensic classification as the pre-optimization
implementation.

The reference oracle ``_legacy_classify`` replicates the original
:meth:`EvidenceClassifier.classify` behaviour using the *unchanged*
primitives (``parse_attributes``, ``indicators_for``, ``is_supported``,
``build_entry``, ``build_corpus``, ``correlate``, ``evaluate``,
``min_corroborating_families``) so the new index path is validated against
the historical behaviour, not against itself.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict

from app.services.evidence_classifier import (
    HIGH,
    LOW,
    MEDIUM,
    INSUFFICIENT_EVIDENCE,
    UNKNOWN,
    build_corpus,
    build_corpus_index,
    correlate_indexed,
    evidence_classifier,
    parse_attributes,
)
from app.services.evidence_classifier.classifier import Classification
from app.services.evidence_classifier.correlation import (
    build_entry,
    correlate,
)
from app.services.evidence_classifier.indicators import (
    indicators_for,
    is_supported,
)
from app.services.evidence_classifier.scorer import (
    evaluate,
    min_corroborating_families,
)

VALID_SEVERITIES = (LOW, MEDIUM, HIGH, UNKNOWN, INSUFFICIENT_EVIDENCE)


# ==============================================================================
# Legacy reference implementation (unchanged primitives only)
# ==============================================================================


def _format_reason(template: str, attributes: dict) -> str:
    safe = defaultdict(str, attributes)

    try:
        return template.format_map(safe)
    except (KeyError, ValueError):
        return template


def _legacy_classify(
    plugin: str,
    artifact_type: str,
    artifact_value: str | None,
    corpus: list[dict] | None,
    evidence_id: int | None,
) -> Classification:
    """Replica of the pre-index ``classify`` used only as a test oracle."""

    attributes = parse_attributes(artifact_value)

    if attributes is None or not attributes:
        return Classification(
            severity=UNKNOWN,
            reasons=[
                "evidence attributes could not be parsed - "
                "no semantic data available to classify"
            ],
        )

    if not is_supported(artifact_type):
        return Classification(
            severity=INSUFFICIENT_EVIDENCE,
            reasons=[
                f"artifact type '{artifact_type}' has no risk indicators - "
                "insufficient evidence to classify"
            ],
        )

    matched = [
        indicator
        for indicator in indicators_for(artifact_type)
        if indicator.match(attributes)
    ]

    base_score = sum(indicator.weight for indicator in matched)
    has_strong = any(indicator.strong for indicator in matched)

    corroborated = False
    correlation = None

    entry = build_entry(
        evidence_id=evidence_id,
        plugin=plugin,
        artifact_type=artifact_type,
        artifact_value=artifact_value,
    )

    if corpus and entry is not None:
        correlation = correlate(
            entry=entry,
            corpus=build_corpus(corpus),
            min_families=min_corroborating_families(artifact_type),
        )
        corroborated = correlation.corroborated

    severity, score = evaluate(
        base_score=base_score,
        has_strong=has_strong,
        corroborated=corroborated,
    )

    reasons: list[str] = []

    for indicator in matched:
        reasons.append(
            _format_reason(indicator.reason_template, attributes)
        )

    if corroborated and correlation and correlation.evidence:
        if severity in (MEDIUM, HIGH):
            references = ", ".join(
                f"{plugin_name}(#{reference_id})"
                for plugin_name, reference_id in correlation.evidence
            )
            reasons.append(
                f"corroborated by independent plugin evidence: {references}"
            )

    indicators = [indicator.code for indicator in matched]

    return Classification(
        severity=severity,
        reasons=reasons,
        indicators=indicators,
        score=score,
        corroborated=corroborated,
    )


def _classify_fields(classification: Classification) -> dict:
    return {
        "severity": classification.severity,
        "score": classification.score,
        "corroborated": classification.corroborated,
        "indicators": list(classification.indicators),
        "reasons": list(classification.reasons),
    }


def _record(evidence_id, artifact_type, attributes, plugin=None):
    return {
        "id": evidence_id,
        "plugin": plugin or f"windows.{artifact_type}",
        "artifact_type": artifact_type,
        "artifact_value": json.dumps(attributes),
    }


# ==============================================================================
# Representative corpora
# ==============================================================================


def _small_mixed_corpus():
    """Cross-family corpus exercising PID, path, connection, and name joins."""

    return [
        # malware.exe PID 5555 across multiple families.
        {"id": 1, "plugin": "windows.info", "artifact_type": "info",
         "artifact_value": json.dumps({"name": "System", "pid": 4})},
        {"id": 2, "plugin": "windows.pslist", "artifact_type": "pslist",
         "artifact_value": json.dumps(
             {"pid": 5555, "name": "malware.exe", "path": "C:\\Temp\\malware"})},
        {"id": 3, "plugin": "windows.cmdline", "artifact_type": "cmdline",
         "artifact_value": json.dumps(
             {"pid": 5555, "cmd": "C:\\Temp\\malware.exe --connect 10.0.0.5:4444"})},
        {"id": 4, "plugin": "windows.filescan", "artifact_type": "filescan",
         "artifact_value": json.dumps(
             {"offset": "0x1", "name": "C:\\Temp\\malware.exe", "size": 123456})},
        {"id": 5, "plugin": "windows.netscan", "artifact_type": "netscan",
         "artifact_value": json.dumps(
             {"pid": 5555, "remote_ip": "10.0.0.5", "remote_port": 4444,
              "state": "ESTABLISHED"})},
        {"id": 6, "plugin": "windows.malfind", "artifact_type": "malfind",
         "artifact_value": json.dumps(
             {"pid": 5555, "protection": "PAGE_EXECUTE_READWRITE",
              "disasm": "db"})},
        {"id": 7, "plugin": "windows.dlllist", "artifact_type": "dlllist",
         "artifact_value": json.dumps(
             {"pid": 5555, "name": "C:\\Temp\\helper.dll"})},
        # Benign explorer.exe PID 1234.
        {"id": 8, "plugin": "windows.pslist", "artifact_type": "pslist",
         "artifact_value": json.dumps(
             {"pid": 1234, "name": "explorer.exe", "path": "C:\\Windows"})},
        {"id": 9, "plugin": "windows.cmdline", "artifact_type": "cmdline",
         "artifact_value": json.dumps({"pid": 1234, "cmd": "explorer.exe"})},
        # Distinct recon PID 4321.
        {"id": 10, "plugin": "windows.pslist", "artifact_type": "pslist",
         "artifact_value": json.dumps(
             {"pid": 4321, "name": "cmd.exe", "path": "C:\\Windows\\System32"})},
        {"id": 11, "plugin": "windows.cmdline", "artifact_type": "cmdline",
         "artifact_value": json.dumps({"pid": 4321, "cmd": "cmd.exe /c whoami"})},
        # Malformed / non-JSON rows must never break correlation.
        {"id": 12, "plugin": "windows.info", "artifact_type": "info",
         "artifact_value": "not-valid-json"},
        {"id": 13, "plugin": "windows.filescan", "artifact_type": "filescan",
         "artifact_value": ""},
    ]


def _bulk_dlllist_corpus(pid: int, dll_count: int = 600):
    """One PID with a large same-family group (the O(n^2) worst case)."""

    corpus = [
        _record(1, "pslist", {"pid": pid, "name": "bigproc.exe",
                              "path": "C:\\Users\\Public\\bigproc.exe"}),
        _record(105, "cmdline", {"pid": pid,
                                 "cmd": "C:\\Users\\Public\\bigproc.exe --enc"}),
        _record(211, "netscan", {"pid": pid, "remote_ip": "8.8.8.8",
                                 "remote_port": 443, "state": "ESTABLISHED"}),
        _record(399, "filescan", {"offset": "0x99",
                                  "name": "C:\\Users\\Public\\bigproc.exe"}),
    ]

    next_id = 500
    for index in range(dll_count):
        corpus.append(
            _record(
                next_id + index,
                "dlllist",
                {"pid": pid, "name": f"C:\\Windows\\System32\\mod{index}.dll"},
            )
        )

    return corpus


# ==============================================================================
# Correlation-layer equivalence (exhaustive over every record)
# ==============================================================================


def _assert_correlation_equivalence(corpus: list[dict]) -> None:
    entries = build_corpus(corpus)
    index = build_corpus_index(entries)

    for position, entry in enumerate(entries):

        legacy = correlate(
            entry=entry,
            corpus=entries,
            min_families=min_corroborating_families(entry.artifact_type),
        )
        optimized = correlate_indexed(
            entry=entry,
            index=index,
            min_families=min_corroborating_families(entry.artifact_type),
        )

        assert optimized.corroborated == legacy.corroborated, (
            f"corroborated mismatch at position {position}"
        )
        assert optimized.families == legacy.families, (
            f"families mismatch at position {position}: "
            f"{optimized.families} != {legacy.families}"
        )
        assert optimized.evidence == legacy.evidence, (
            f"evidence mismatch at position {position}: "
            f"{optimized.evidence} != {legacy.evidence}"
        )


def test_correlate_indexed_matches_legacy_small_mixed():
    _assert_correlation_equivalence(_small_mixed_corpus())


def test_correlate_indexed_matches_legacy_bulk_dlllist():
    _assert_correlation_equivalence(_bulk_dlllist_corpus(pid=4444, dll_count=600))


def test_correlate_indexed_matches_legacy_large_multi_pid_corpus():
    corpus: list[dict] = []
    evidence_id = 1

    for pid in range(10, 60):
        corpus.append(
            _record(evidence_id, "pslist",
                    {"pid": pid, "name": f"proc{pid}.exe",
                     "path": "C:\\Program Files\\proc%d.exe" % pid})
        )
        evidence_id += 1
        corpus.append(
            _record(evidence_id, "cmdline",
                    {"pid": pid, "cmd": f"proc{pid}.exe --flag"})
        )
        evidence_id += 1
        for module in range(20):
            corpus.append(
                _record(evidence_id, "dlllist",
                        {"pid": pid, "name": f"C:\\Windows\\mod{module}.dll"})
            )
            evidence_id += 1

    _assert_correlation_equivalence(corpus)


# ==============================================================================
# Full classify-level equivalence (new paths vs legacy oracle)
# ==============================================================================


def _assert_classify_equivalence(corpus: list[dict]) -> None:
    entries = build_corpus(corpus)
    index = build_corpus_index(entries)

    for record in corpus:

        plugin = record["plugin"]
        artifact_type = record["artifact_type"]
        artifact_value = record["artifact_value"]
        evidence_id = record["id"]

        expected = _legacy_classify(
            plugin=plugin,
            artifact_type=artifact_type,
            artifact_value=artifact_value,
            corpus=corpus,
            evidence_id=evidence_id,
        )

        # Path 1: raw list handed to classify (kept for on-demand callers).
        via_list = evidence_classifier.classify(
            plugin=plugin,
            artifact_type=artifact_type,
            artifact_value=artifact_value,
            corpus=corpus,
            evidence_id=evidence_id,
        )

        # Path 2: prebuilt index (used by the batch persistence service).
        via_index = evidence_classifier.classify(
            plugin=plugin,
            artifact_type=artifact_type,
            artifact_value=artifact_value,
            corpus=index,
            evidence_id=evidence_id,
        )

        for path, actual in (("list", via_list), ("index", via_index)):
            assert _classify_fields(actual) == _classify_fields(expected), (
                f"classify({path}) mismatch for record {evidence_id} "
                f"({artifact_type}): {_classify_fields(actual)} != "
                f"{_classify_fields(expected)}"
            )


def test_classify_matches_legacy_small_mixed():
    _assert_classify_equivalence(_small_mixed_corpus())


def test_classify_matches_legacy_bulk_dlllist():
    _assert_classify_equivalence(_bulk_dlllist_corpus(pid=7777, dll_count=300))


def test_classify_matches_legacy_without_corpus():
    """No-corpus behaviour is unchanged and severity lives in VALID_SEVERITIES."""

    standalone = evidence_classifier.classify(
        plugin="windows.cmdline",
        artifact_type="cmdline",
        artifact_value=json.dumps(
            {"pid": 5555, "cmd": "C:\\Temp\\malware.exe --connect 10.0.0.5:4444"}
        ),
    )
    expected = _legacy_classify(
        plugin="windows.cmdline",
        artifact_type="cmdline",
        artifact_value=json.dumps(
            {"pid": 5555, "cmd": "C:\\Temp\\malware.exe --connect 10.0.0.5:4444"}
        ),
        corpus=None,
        evidence_id=None,
    )
    assert _classify_fields(standalone) == _classify_fields(expected)
    assert standalone.severity in VALID_SEVERITIES


# ==============================================================================
# Large-corpus scalability (the original ~47 minute path)
# ==============================================================================


def _large_realistic_corpus() -> list[dict]:
    """
    ~20k rows approximating a real 1.6 GB investigation: 50 processes, one
    with a 13k handle group, plus bulk dlllist/cmdline/netscan rows. Sized to
    keep the test fast while reproducing the same scale class as
    INV-20260812-B8E7AE (19,392 rows).
    """

    corpus: list[dict] = []
    evidence_id = 1

    for pid in range(1000, 2000, 10):
        corpus.append(
            _record(evidence_id, "pslist",
                    {"pid": pid, "name": "svchost.exe",
                     "path": "C:\\Windows\\System32\\svchost.exe"})
        )
        evidence_id += 1
        corpus.append(
            _record(evidence_id, "cmdline",
                    {"pid": pid, "cmd": "svchost.exe -k -p"})
        )
        evidence_id += 1
        for nets in range(14):
            corpus.append(
                _record(evidence_id, "netscan",
                        {"pid": pid, "remote_ip": f"10.1.1.{pid % 250}",
                         "remote_port": 443 + nets, "state": "ESTABLISHED"})
            )
            evidence_id += 1

    # One 'busy' PID carrying a large handle family plus dlllist bulk.
    busy_pid = 9999
    for handle in range(16000):
        corpus.append(
            _record(evidence_id, "handles",
                    {"pid": busy_pid, "object": f"File 0x{handle:x}",
                     "type": "File", "handlevalue": str(handle)})
        )
        evidence_id += 1
    for module in range(3000):
        corpus.append(
            _record(evidence_id, "dlllist",
                    {"pid": busy_pid,
                     "name": f"C:\\Windows\\System32\\m{module}.dll"})
        )
        evidence_id += 1

    corpus.append(
        _record(evidence_id, "pslist",
                {"pid": busy_pid, "name": "busy.exe",
                 "path": "C:\\Users\\Public\\busy.exe"})
    )
    evidence_id += 1

    # A few genuinely suspicious rows so HIGH/medium paths execute.
    corpus.append(
        _record(evidence_id, "cmdline",
                {"pid": 31337, "cmd": "C:\\Temp\\evil.exe --connect 10.0.0.9:4444"})
    )
    evidence_id += 1
    corpus.append(
        _record(evidence_id, "pslist",
                {"pid": 31337, "name": "evil.exe", "path": "C:\\Temp\\evil"})
    )
    evidence_id += 1
    corpus.append(
        _record(evidence_id, "malfind",
                {"pid": 31337, "protection": "PAGE_EXECUTE_READWRITE",
                 "disasm": "db"})
    )
    evidence_id += 1

    return corpus


def test_large_corpus_classification_scales_linearly():
    """~20k rows classify in seconds via the prebuilt index (not ~47 minutes)."""

    corpus = _large_realistic_corpus()
    assert len(corpus) >= 20000

    started = time.monotonic()

    entries = build_corpus(corpus)
    index = build_corpus_index(entries)

    severity_counts: dict[str, int] = {}

    for record in corpus:
        result = evidence_classifier.classify(
            plugin=record["plugin"],
            artifact_type=record["artifact_type"],
            artifact_value=record["artifact_value"],
            corpus=index,
            evidence_id=record["id"],
        )
        severity_counts[result.severity] = (
            severity_counts.get(result.severity, 0) + 1
        )

    elapsed = time.monotonic() - started

    # Linear-scale expectation: the same 20k corpus at the pre-fix
    # ~0.16 s/record rate would take roughly 53 minutes. The indexed path
    # must finish in seconds.
    assert elapsed < 60.0, f"classification took {elapsed:.2f}s (>= 60s)"

    assert sum(severity_counts.values()) == len(corpus)
    assert severity_counts.get("high", 0) >= 1, (
        f"expected at least one HIGH finding, got {severity_counts}"
    )


def test_large_corpus_indexed_results_match_legacy_spot_check():
    """Spot-check the 20k corpus against the legacy oracle on a sample."""

    corpus = _large_realistic_corpus()
    entries = build_corpus(corpus)
    index = build_corpus_index(entries)

    checked = 0

    for position in range(0, len(corpus), len(corpus) // 40):

        record = corpus[position]

        expected = _legacy_classify(
            plugin=record["plugin"],
            artifact_type=record["artifact_type"],
            artifact_value=record["artifact_value"],
            corpus=corpus,
            evidence_id=record["id"],
        )
        actual = evidence_classifier.classify(
            plugin=record["plugin"],
            artifact_type=record["artifact_type"],
            artifact_value=record["artifact_value"],
            corpus=index,
            evidence_id=record["id"],
        )

        assert _classify_fields(actual) == _classify_fields(expected), (
            f"mismatch at position {position} ({record['artifact_type']})"
        )
        checked += 1

    assert checked >= 10