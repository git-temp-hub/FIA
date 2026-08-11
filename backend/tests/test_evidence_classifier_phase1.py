"""
Phase 1 tests: persistence + severity filter correctness.

Covers:
- backward-compatible, idempotent migration of the risk columns
- repository severity filter operating on the persisted ``risk_level``
- ``classify_investigation_evidence`` persisting classifier output
- severity filter/pagination using the classifier's severity (not confidence)
- serialization preferring persisted classification over on-the-fly derivation
"""

from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy import text

from app.api.routes.evidence import router as evidence_router
from app.database.database import get_db
from app.database.repositories import PluginResultRepository
from app.models.case import Case
from app.models.memory_dump import MemoryDump
from app.models.plugin_execution import PluginExecution
from app.models.plugin_result import PluginResult
from app.services.risk_classification_service import (
    classify_investigation_evidence,
)

SAMPLE_ATTRIBUTES = [
    {"artifact_type": "info", "plugin": "windows.info",
     "attributes": {"name": "System", "pid": 4, "state": "running"}},
    {"artifact_type": "info", "plugin": "windows.info",
     "attributes": {"name": "explorer.exe", "pid": 1234, "state": "running"}},
    {"artifact_type": "pslist", "plugin": "windows.pslist",
     "attributes": {"pid": 1234, "name": "explorer.exe", "path": "C:\\Windows"}},
    {"artifact_type": "pslist", "plugin": "windows.pslist",
     "attributes": {"pid": 5555, "name": "malware.exe", "path": "C:\\Temp\\malware"}},
    {"artifact_type": "pslist", "plugin": "windows.pslist",
     "attributes": {"pid": 4321, "name": "cmd.exe", "path": "C:\\Windows\\System32"}},
    {"artifact_type": "cmdline", "plugin": "windows.cmdline",
     "attributes": {"pid": 4321, "cmd": "cmd.exe /c whoami"}},
    {"artifact_type": "cmdline", "plugin": "windows.cmdline",
     "attributes": {"pid": 5555, "cmd": "C:\\Temp\\malware.exe --connect 10.0.0.5:4444"}},
    {"artifact_type": "cmdline", "plugin": "windows.cmdline",
     "attributes": {"pid": 1234, "cmd": "explorer.exe"}},
    {"artifact_type": "filescan", "plugin": "windows.filescan",
     "attributes": {"offset": "0x1", "name": "C:\\Temp\\malware.exe", "size": 123456}},
    {"artifact_type": "filescan", "plugin": "windows.filescan",
     "attributes": {"offset": "0x2", "name": "C:\\Windows\\System32\\svchost.exe", "size": 50000}},
]

def _seed_investigation(session, investigation_id="INV-P1"):
    case = Case(case_name=investigation_id, investigator="tester", description="t")
    session.add(case)
    session.flush()

    dump = MemoryDump(
        case_id=case.id,
        investigation_id=investigation_id,
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

    for index, item in enumerate(SAMPLE_ATTRIBUTES):
        execution = PluginExecution(
            memory_dump_id=dump.id,
            plugin_name=item["plugin"],
            execution_status="completed",
        )
        session.add(execution)
        session.flush()

        result = PluginResult(
            plugin_execution_id=execution.id,
            artifact_type=item["artifact_type"],
            artifact_name=item["plugin"],
            artifact_value=json.dumps(item["attributes"]),
            confidence_score=100,
        )
        session.add(result)

    session.commit()

    return investigation_id


# ==============================================================================
# Migration
# ==============================================================================


def test_risk_columns_migration_is_backward_compatible(tmp_path):
    db_path = tmp_path / "legacy.db"

    legacy = create_engine(f"sqlite:///{db_path.as_posix()}")
    with legacy.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE plugin_results ("
                "id INTEGER PRIMARY KEY, "
                "plugin_execution_id INTEGER NOT NULL, "
                "artifact_type VARCHAR(100) NOT NULL, "
                "artifact_name VARCHAR(255) NOT NULL, "
                "artifact_value VARCHAR(5000) NOT NULL, "
                "confidence_score INTEGER NOT NULL DEFAULT 100, "
                "created_at DATETIME NOT NULL"
                ")"
            )
        )
        connection.execute(
            text(
                "INSERT INTO plugin_results (id, plugin_execution_id, "
                "artifact_type, artifact_name, artifact_value, "
                "confidence_score, created_at) "
                "VALUES (1, 1, 'pslist', 'windows.pslist', '{}', 100, "
                "'2026-01-01 00:00:00')"
            )
        )

    from app.database.database import ensure_evidence_risk_columns

    ensure_evidence_risk_columns(legacy)

    with legacy.connect() as connection:
        columns = {
            row[1]
            for row in connection.execute(
                text("PRAGMA table_info(plugin_results)")
            )
        }
        for expected in ("risk_level", "risk_reasons", "risk_indicators", "rule_version"):
            assert expected in columns

        (artifact_name,) = connection.execute(
            text("SELECT artifact_name FROM plugin_results WHERE id = 1")
        ).fetchone()
        assert artifact_name == "windows.pslist"

    # Idempotent: running again must not error or duplicate columns.
    ensure_evidence_risk_columns(legacy)

    with legacy.connect() as connection:
        rows = connection.execute(
            text("PRAGMA table_info(plugin_results)")
        ).fetchall()
        column_names = [row[1] for row in rows]
        for expected in ("risk_level", "risk_reasons", "risk_indicators", "rule_version"):
            assert column_names.count(expected) == 1

    legacy.dispose()


def test_risk_columns_migration_skips_when_table_missing(tmp_path):
    from app.database.database import ensure_evidence_risk_columns

    engine = create_engine(
        f"sqlite:///{(tmp_path / 'empty.db').as_posix()}"
    )
    # Must not raise when the table does not exist.
    ensure_evidence_risk_columns(engine)
    engine.dispose()


# ==============================================================================
# Repository filter on risk_level
# ==============================================================================


def test_severity_filter_uses_risk_level(session, session_factory):
    _seed_investigation(session, "INV-FILTER")

    classify_investigation_evidence(session, "INV-FILTER")

    repository = PluginResultRepository(session_factory())

    high, total = repository.search(
        investigation_id="INV-FILTER",
        severity="high",
    )
    assert total == 1
    assert high[0].artifact_type == "cmdline"

    # medium: pslist malware.exe + cmdline whoami (recon) + filescan malware.exe
    medium, total_medium = repository.search(
        investigation_id="INV-FILTER",
        severity="medium",
    )
    assert total_medium == 3
    assert {row.artifact_type for row in medium} == {"pslist", "cmdline", "filescan"}

    low, total_low = repository.search(
        investigation_id="INV-FILTER",
        severity="low",
    )
    assert total_low == 6

    # Unscoped search still returns everything.
    _, total_all = repository.search(investigation_id="INV-FILTER")
    assert total_all == 10


def test_legacy_unclassified_rows_excluded_from_severity_filter(session, session_factory):
    _seed_investigation(session, "INV-LEGACY")

    # Do NOT run the classification pass: risk_level stays NULL.
    repository = PluginResultRepository(session_factory())

    for severity in ("high", "medium", "low", "unknown"):
        _, total = repository.search(
            investigation_id="INV-LEGACY",
            severity=severity,
        )
        assert total == 0


# ==============================================================================
# Persistence service
# ==============================================================================


def test_classify_investigation_evidence_persists(session):
    investigation_id = _seed_investigation(session, "INV-PERSIST")

    updated = classify_investigation_evidence(session, investigation_id)
    assert updated == 10

    repository = PluginResultRepository(session)

    records = repository.get_by_investigation(investigation_id)
    assert len(records) == 10

    for record in records:
        assert record.risk_level in ("low", "medium", "high")
        assert record.rule_version == "1.0"
        assert record.risk_reasons is not None
        assert record.risk_indicators is not None

    by_type = {}
    for record in records:
        by_type.setdefault(record.artifact_type, []).append(record)

    assert by_type["info"][0].risk_level == "low"
    assert {row.risk_level for row in by_type["pslist"]} == {"low", "medium"}
    assert {row.risk_level for row in by_type["cmdline"]} == {"low", "medium", "high"}
    assert {row.risk_level for row in by_type["filescan"]} == {"low", "medium"}

    # The HIGH record must carry reasons and indicator codes.
    high_record = next(
        record for record in records
        if record.risk_level == "high"
    )
    reasons = json.loads(high_record.risk_reasons)
    indicators = json.loads(high_record.risk_indicators)
    assert "CMD-01" in indicators
    assert len(reasons) >= 2


def test_classify_investigation_evidence_is_idempotent(session):
    investigation_id = _seed_investigation(session, "INV-IDEMP")

    classify_investigation_evidence(session, investigation_id)
    second = classify_investigation_evidence(session, investigation_id)

    assert second == 0


# ==============================================================================
# API: filter + serialization use persisted classification
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


def test_api_severity_filter_uses_classifier_severity(evidence_client, session):
    investigation_id = _seed_investigation(session, "INV-API")
    classify_investigation_evidence(session, investigation_id)

    response = evidence_client.get(
        "/evidence/",
        params={"investigation_id": investigation_id, "severity": "high"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["artifact_type"] == "cmdline"
    assert payload["items"][0]["severity"] == "high"

    response = evidence_client.get(
        "/evidence/",
        params={"investigation_id": investigation_id, "severity": "medium"},
    )
    assert response.json()["total"] == 3


def test_serialization_prefers_persisted_risk_level(evidence_client, session):
    investigation_id = _seed_investigation(session, "INV-OVERRIDE")

    repository = PluginResultRepository(session)
    records = repository.get_by_investigation(investigation_id)

    # The high-risk cmdline row would derive "high" on the fly; force "low".
    cmdline = next(
        record for record in records
        if record.artifact_type == "cmdline"
        and "--connect" in record.artifact_value
    )
    cmdline.risk_level = "low"
    cmdline.risk_reasons = json.dumps(["suppressed by analyst"])
    cmdline.risk_indicators = json.dumps([])
    session.commit()

    response = evidence_client.get(
        "/evidence/",
        params={"investigation_id": investigation_id},
    )
    items = response.json()["items"]
    item = next(i for i in items if i["id"] == cmdline.id)
    assert item["severity"] == "low"
    assert item["risk_reasons"] == ["suppressed by analyst"]
