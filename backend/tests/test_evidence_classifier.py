"""
Regression tests for the Phase 0 EvidenceClassifier.

Covers:
- benign info/pslist/filescan/cmdline -> LOW
- suspicious cmdline / network activity -> MEDIUM
- user-writable executable paths -> elevated risk (with corroboration)
- cross-plugin PID/file/connection correlation -> escalation
- keyword alone must NOT create HIGH
- severity independent of confidence_score
- UNKNOWN / INSUFFICIENT-EVIDENCE states
- scoring threshold boundaries
- API serialization shape unchanged (additive fields only)
"""

from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.evidence import router as evidence_router
from app.database.database import get_db
from app.models.case import Case
from app.models.memory_dump import MemoryDump
from app.models.plugin_execution import PluginExecution
from app.models.plugin_result import PluginResult
from app.services.evidence_classifier import evidence_classifier
from app.services.evidence_classifier.scorer import (
    HIGH,
    LOW,
    MEDIUM,
    UNKNOWN,
    INSUFFICIENT_EVIDENCE,
    evaluate,
    min_corroborating_families,
)

# ==============================================================================
# Sample evidence (mirrors the current investigation's 10 rows)
# ==============================================================================

SAMPLE_CORPUS = [
    {"id": 1, "plugin": "windows.info", "artifact_type": "info",
     "artifact_value": json.dumps({"name": "System", "pid": 4, "state": "running"})},
    {"id": 2, "plugin": "windows.info", "artifact_type": "info",
     "artifact_value": json.dumps({"name": "explorer.exe", "pid": 1234, "state": "running"})},
    {"id": 3, "plugin": "windows.pslist", "artifact_type": "pslist",
     "artifact_value": json.dumps({"pid": 1234, "name": "explorer.exe", "path": "C:\\Windows"})},
    {"id": 4, "plugin": "windows.pslist", "artifact_type": "pslist",
     "artifact_value": json.dumps({"pid": 5555, "name": "malware.exe", "path": "C:\\Temp\\malware"})},
    {"id": 5, "plugin": "windows.pslist", "artifact_type": "pslist",
     "artifact_value": json.dumps({"pid": 4321, "name": "cmd.exe", "path": "C:\\Windows\\System32"})},
    {"id": 6, "plugin": "windows.cmdline", "artifact_type": "cmdline",
     "artifact_value": json.dumps({"pid": 4321, "cmd": "cmd.exe /c whoami"})},
    {"id": 7, "plugin": "windows.cmdline", "artifact_type": "cmdline",
     "artifact_value": json.dumps({"pid": 5555, "cmd": "C:\\Temp\\malware.exe --connect 10.0.0.5:4444"})},
    {"id": 8, "plugin": "windows.cmdline", "artifact_type": "cmdline",
     "artifact_value": json.dumps({"pid": 1234, "cmd": "explorer.exe"})},
    {"id": 9, "plugin": "windows.filescan", "artifact_type": "filescan",
     "artifact_value": json.dumps({"offset": "0x1", "name": "C:\\Temp\\malware.exe", "size": 123456})},
    {"id": 10, "plugin": "windows.filescan", "artifact_type": "filescan",
     "artifact_value": json.dumps({"offset": "0x2", "name": "C:\\Windows\\System32\\svchost.exe", "size": 50000})},
]


def _record(artifact_type, attributes, evidence_id=None, plugin="windows.pslist"):
    return {
        "id": evidence_id,
        "plugin": plugin,
        "artifact_type": artifact_type,
        "artifact_value": json.dumps(attributes),
    }


# ==============================================================================
# Benign artifacts -> LOW
# ==============================================================================


def test_benign_info_is_low():
    classification = evidence_classifier.classify(
        plugin="windows.info",
        artifact_type="info",
        artifact_value=json.dumps({"name": "System", "pid": 4}),
        corpus=SAMPLE_CORPUS,
        evidence_id=1,
    )
    assert classification.severity == LOW


def test_benign_pslist_is_low():
    classification = evidence_classifier.classify(
        plugin="windows.pslist",
        artifact_type="pslist",
        artifact_value=json.dumps(
            {"pid": 4321, "name": "cmd.exe", "path": "C:\\Windows\\System32"}
        ),
        corpus=SAMPLE_CORPUS,
        evidence_id=5,
    )
    assert classification.severity == LOW


def test_benign_explorer_pslist_is_low_even_with_matching_cmdline():
    classification = evidence_classifier.classify(
        plugin="windows.pslist",
        artifact_type="pslist",
        artifact_value=json.dumps(
            {"pid": 1234, "name": "explorer.exe", "path": "C:\\Windows"}
        ),
        corpus=SAMPLE_CORPUS,
        evidence_id=3,
    )
    assert classification.severity == LOW


def test_benign_filescan_is_low():
    classification = evidence_classifier.classify(
        plugin="windows.filescan",
        artifact_type="filescan",
        artifact_value=json.dumps(
            {"offset": "0x2", "name": "C:\\Windows\\System32\\svchost.exe", "size": 50000}
        ),
        corpus=SAMPLE_CORPUS,
        evidence_id=10,
    )
    assert classification.severity == LOW


def test_benign_cmdline_is_low():
    classification = evidence_classifier.classify(
        plugin="windows.cmdline",
        artifact_type="cmdline",
        artifact_value=json.dumps({"pid": 1234, "cmd": "explorer.exe"}),
        corpus=SAMPLE_CORPUS,
        evidence_id=8,
    )
    assert classification.severity == LOW


# ==============================================================================
# Suspicious cmdline / network -> MEDIUM (without corroboration)
# ==============================================================================


def test_recon_cmdline_is_medium():
    classification = evidence_classifier.classify(
        plugin="windows.cmdline",
        artifact_type="cmdline",
        artifact_value=json.dumps({"pid": 4321, "cmd": "cmd.exe /c whoami"}),
        corpus=SAMPLE_CORPUS,
        evidence_id=6,
    )
    assert classification.severity == MEDIUM
    assert "CMD-02" in classification.indicators
    assert classification.reasons


def test_remote_endpoint_cmdline_is_medium_without_corpus():
    classification = evidence_classifier.classify(
        plugin="windows.cmdline",
        artifact_type="cmdline",
        artifact_value=json.dumps(
            {"pid": 5555, "cmd": "C:\\Temp\\malware.exe --connect 10.0.0.5:4444"}
        ),
    )
    # Strong signal alone -> MEDIUM, never HIGH without corroboration.
    assert classification.severity == MEDIUM
    assert classification.corroborated is False


def test_suspicious_netscan_is_medium():
    classification = evidence_classifier.classify(
        plugin="windows.netscan",
        artifact_type="netscan",
        artifact_value=json.dumps(
            {"pid": 5555, "remote_ip": "10.0.0.5", "remote_port": 4444, "state": "ESTABLISHED"}
        ),
    )
    assert classification.severity == MEDIUM
    assert "NS-01" in classification.indicators


def test_loopback_netscan_is_low():
    classification = evidence_classifier.classify(
        plugin="windows.netscan",
        artifact_type="netscan",
        artifact_value=json.dumps(
            {"pid": 1234, "remote_ip": "127.0.0.1", "remote_port": 135, "state": "ESTABLISHED"}
        ),
    )
    assert classification.severity == LOW


# ==============================================================================
# User-writable executable paths -> elevated risk with corroboration
# ==============================================================================


def test_user_writable_exe_path_alone_is_low():
    classification = evidence_classifier.classify(
        plugin="windows.pslist",
        artifact_type="pslist",
        artifact_value=json.dumps(
            {"pid": 5555, "name": "malware.exe", "path": "C:\\Temp\\malware"}
        ),
    )
    # Weak signal (weight 2) without corroboration stays LOW.
    assert classification.severity == LOW


def test_user_writable_exe_path_elevates_with_corpus():
    classification = evidence_classifier.classify(
        plugin="windows.pslist",
        artifact_type="pslist",
        artifact_value=json.dumps(
            {"pid": 5555, "name": "malware.exe", "path": "C:\\Temp\\malware"}
        ),
        corpus=SAMPLE_CORPUS,
        evidence_id=4,
    )
    assert classification.severity == MEDIUM
    assert "PSL-01" in classification.indicators
    assert classification.corroborated is True


def test_user_writable_filescan_elevates_with_corpus():
    classification = evidence_classifier.classify(
        plugin="windows.filescan",
        artifact_type="filescan",
        artifact_value=json.dumps(
            {"offset": "0x1", "name": "C:\\Temp\\malware.exe", "size": 123456}
        ),
        corpus=SAMPLE_CORPUS,
        evidence_id=9,
    )
    assert classification.severity == MEDIUM
    assert "FS-01" in classification.indicators


# ==============================================================================
# Cross-plugin correlation -> escalation
# ==============================================================================


def test_cross_plugin_pid_correlation_escalates_to_high():
    classification = evidence_classifier.classify(
        plugin="windows.cmdline",
        artifact_type="cmdline",
        artifact_value=json.dumps(
            {"pid": 5555, "cmd": "C:\\Temp\\malware.exe --connect 10.0.0.5:4444"}
        ),
        corpus=SAMPLE_CORPUS,
        evidence_id=7,
    )
    assert classification.severity == HIGH
    assert classification.corroborated is True
    assert "CMD-01" in classification.indicators
    assert classification.reasons


def test_file_process_connection_correlation_matches():
    # The netscan connection (10.0.0.5:4444) is corroborated by a cmdline
    # record carrying the same endpoint (connection entity) and a pslist
    # record for the same PID (process entity).
    corpus = [
        _record("pslist", {"pid": 5555, "name": "malware.exe", "path": "C:\\Temp\\malware"}, 4),
        _record("filescan", {"offset": "0x1", "name": "C:\\Temp\\malware.exe", "size": 123456}, 9),
        _record("cmdline", {"pid": 5555, "cmd": "C:\\Temp\\malware.exe --connect 10.0.0.5:4444"}, 7),
    ]
    classification = evidence_classifier.classify(
        plugin="windows.netscan",
        artifact_type="netscan",
        artifact_value=json.dumps(
            {"pid": 5555, "remote_ip": "10.0.0.5", "remote_port": 4444, "state": "ESTABLISHED"}
        ),
        corpus=corpus,
        evidence_id=11,
    )
    # strong (NS-01) + corroborated (pslist + cmdline) -> HIGH
    assert classification.severity == HIGH


def test_single_family_path_correlation_is_not_enough():
    corpus = [
        _record("pslist", {"pid": 5555, "name": "malware.exe", "path": "C:\\Temp\\malware"}, 4),
    ]
    classification = evidence_classifier.classify(
        plugin="windows.filescan",
        artifact_type="filescan",
        artifact_value=json.dumps(
            {"offset": "0x1", "name": "C:\\Temp\\malware.exe", "size": 123456}
        ),
        corpus=corpus,
        evidence_id=9,
    )
    # Only one corroborating family (pslist) -> no boost -> base 2 -> LOW.
    assert classification.severity == LOW


def test_cmdline_file_path_correlation_elevates():
    # A weak cmdline record (executable in a user-writable path, CMD-04)
    # is corroborated by pslist (same PID) and filescan (same path stem).
    corpus = [
        _record("pslist", {"pid": 5555, "name": "malware.exe", "path": "C:\\Temp\\malware"}, 4),
        _record("filescan", {"offset": "0x1", "name": "C:\\Temp\\malware.exe", "size": 123456}, 9),
    ]
    classification = evidence_classifier.classify(
        plugin="windows.cmdline",
        artifact_type="cmdline",
        artifact_value=json.dumps(
            {"pid": 5555, "cmd": "C:\\Temp\\malware.exe -start"}
        ),
        corpus=corpus,
        evidence_id=77,
    )
    assert "CMD-04" in classification.indicators
    assert classification.corroborated is True
    assert classification.severity == MEDIUM


# ==============================================================================
# Corroboration escalation
# ==============================================================================


def test_corroboration_boosts_weak_signal_to_medium():
    # FS-01 (weight 2) corroborated by pslist + cmdline -> MEDIUM.
    corpus = [
        _record("pslist", {"pid": 5555, "name": "malware.exe", "path": "C:\\Temp\\malware"}, 4),
        _record("cmdline", {"pid": 5555, "cmd": "C:\\Temp\\malware.exe -start"}, 7),
    ]
    classification = evidence_classifier.classify(
        plugin="windows.filescan",
        artifact_type="filescan",
        artifact_value=json.dumps(
            {"offset": "0x1", "name": "C:\\Temp\\malware.exe", "size": 123456}
        ),
        corpus=corpus,
        evidence_id=9,
    )
    assert classification.severity == MEDIUM
    assert classification.corroborated is True


def test_weak_keyword_alone_never_high():
    # Encoding marker (CMD-03, weight 2, weak) alone -> LOW, never HIGH.
    classification = evidence_classifier.classify(
        plugin="windows.cmdline",
        artifact_type="cmdline",
        artifact_value=json.dumps(
            {"pid": 7777, "cmd": "powershell -enc SQBFAFgA"}
        ),
    )
    assert classification.severity == LOW
    assert "CMD-03" in classification.indicators


# ==============================================================================
# HIGH threshold boundaries (pure scorer)
# ==============================================================================


def test_scorer_high_boundary_at_six():
    severity, score = evaluate(base_score=2, has_strong=True, corroborated=True)
    assert score == 6
    assert severity == HIGH


def test_scorer_medium_below_high_boundary():
    severity, score = evaluate(base_score=1, has_strong=True, corroborated=True)
    assert score == 5
    assert severity == MEDIUM


def test_scorer_medium_boundary_at_three():
    severity, score = evaluate(base_score=3, has_strong=False, corroborated=False)
    assert score == 3
    assert severity == MEDIUM


def test_scorer_low_below_medium_boundary():
    severity, score = evaluate(base_score=2, has_strong=False, corroborated=False)
    assert score == 2
    assert severity == LOW


def test_scorer_strong_without_corroboration_is_never_high():
    severity, score = evaluate(base_score=6, has_strong=True, corroborated=False)
    assert score == 6
    assert severity == MEDIUM


def test_scorer_existence_alone_is_never_high():
    severity, score = evaluate(base_score=0, has_strong=False, corroborated=True)
    assert score == 2
    assert severity == LOW


def test_malfind_requires_only_one_corroborating_family():
    assert min_corroborating_families("malfind") == 1
    assert min_corroborating_families("cmdline") == 2


def test_malfind_medium_without_corrob_and_high_with_single_family():
    malicious = json.dumps(
        {"pid": 5555, "protection": "PAGE_EXECUTE_READWRITE", "disasm": "db"}
    )
    alone = evidence_classifier.classify(
        plugin="windows.malfind",
        artifact_type="malfind",
        artifact_value=malicious,
    )
    assert alone.severity == MEDIUM

    corpus = [
        _record("pslist", {"pid": 5555, "name": "malware.exe", "path": "C:\\Temp\\malware"}, 4),
    ]
    corroborated = evidence_classifier.classify(
        plugin="windows.malfind",
        artifact_type="malfind",
        artifact_value=malicious,
        corpus=corpus,
        evidence_id=99,
    )
    assert corroborated.severity == HIGH


# ==============================================================================
# UNKNOWN / INSUFFICIENT-EVIDENCE
# ==============================================================================


def test_unparseable_attributes_is_unknown():
    classification = evidence_classifier.classify(
        plugin="windows.pslist",
        artifact_type="pslist",
        artifact_value="not-json",
    )
    assert classification.severity == UNKNOWN


def test_empty_attributes_is_unknown():
    classification = evidence_classifier.classify(
        plugin="windows.pslist",
        artifact_type="pslist",
        artifact_value="",
    )
    assert classification.severity == UNKNOWN


def test_unknown_plugin_is_insufficient_evidence():
    classification = evidence_classifier.classify(
        plugin="windows.foobar",
        artifact_type="foobar",
        artifact_value=json.dumps({"pid": 1}),
    )
    assert classification.severity == INSUFFICIENT_EVIDENCE
    assert classification.reasons


# ==============================================================================
# Severity independence from confidence_score (API level)
# ==============================================================================


@pytest.fixture()
def evidence_client(session_factory):
    test_app = FastAPI()
    test_app.include_router(evidence_router)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    test_app.dependency_overrides[get_db] = override_get_db

    return TestClient(test_app)


def _seed_evidence(session):
    case = Case(case_name="INV-TEST", investigator="tester", description="t")
    session.add(case)
    session.flush()
    dump = MemoryDump(
        case_id=case.id,
        investigation_id="INV-TEST",
        filename="dump.raw",
        original_path="/tmp/dump.raw",
        stored_path="/storage/dump.raw",
        sha256_hash="0" * 64,
        file_size=1024,
        status="completed",
        progress=100,
    )
    session.add(dump)
    session.flush()

    execution = PluginExecution(
        memory_dump_id=dump.id,
        plugin_name="windows.pslist",
        execution_status="completed",
    )
    session.add(execution)
    session.flush()

    attrs = json.dumps({"pid": 5555, "name": "malware.exe", "path": "C:\\Temp\\malware"})

    low_conf = PluginResult(
        plugin_execution_id=execution.id,
        artifact_type="pslist",
        artifact_name="windows.pslist",
        artifact_value=attrs,
        confidence_score=100,
    )
    high_conf = PluginResult(
        plugin_execution_id=execution.id,
        artifact_type="pslist",
        artifact_name="windows.pslist",
        artifact_value=attrs,
        confidence_score=30,
    )
    session.add_all([low_conf, high_conf])
    session.commit()

    return low_conf.id, high_conf.id


def test_severity_is_independent_of_confidence_score(evidence_client, session):
    low_id, high_id = _seed_evidence(session)

    response = evidence_client.get(
        "/evidence/",
        params={"investigation_id": "INV-TEST"},
    )

    assert response.status_code == 200
    payload = response.json()

    items = payload["items"]
    assert len(items) == 2

    by_id = {item["id"]: item for item in items}

    assert by_id[low_id]["confidence_score"] == 100
    assert by_id[high_id]["confidence_score"] == 30
    # Severity/classification must be identical despite different confidence.
    assert by_id[low_id]["severity"] == by_id[high_id]["severity"]
    assert (
        by_id[low_id]["classification_state"]
        == by_id[high_id]["classification_state"]
    )
    # Additive fields present; original fields preserved.
    assert "risk_reasons" in by_id[low_id]
    assert "risk_indicators" in by_id[low_id]
    assert "plugin" in by_id[low_id]
    assert "artifact_type" in by_id[low_id]
    assert "artifact_value" in by_id[low_id]
    assert "created_at" in by_id[low_id]


def test_evidence_detail_shape_unchanged_and_classified(evidence_client, session):
    low_id, high_id = _seed_evidence(session)

    response = evidence_client.get(f"/evidence/{low_id}")

    assert response.status_code == 200
    payload = response.json()

    assert payload["id"] == low_id
    assert payload["plugin"] == "windows.pslist"
    assert payload["confidence_score"] == 100
    assert payload["severity"] == payload["classification_state"]
    assert isinstance(payload["risk_reasons"], list)
    assert isinstance(payload["risk_indicators"], list)
    assert payload["investigation_id"] == "INV-TEST"
