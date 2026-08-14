"""
Regression + performance tests for the Phase-5 SQLite retrieval acceleration.

Phase 5 adds guarded JSON expression indexes (``ix_plugin_results_json_*``)
and an ``artifact_type`` index to ``plugin_results`` so the deterministic
fallback retrieval service can serve exact PID / TID / process-name entity
lookups with index seeks instead of full scans. SQLite remains authoritative;
Chroma stays semantic-only; every query result must be byte-identical to the
pre-index path.

Covered
-------
- Index creation is idempotent and safe with free-text (non-JSON) rows.
- EXPLAIN QUERY PLAN shows ``MULTI-INDEX OR`` / ``USING INDEX`` for the PID,
  TID, and process-name exact lookups once the indexes exist.
- The accelerated ``_fetch_process_names`` (exact index + LIKE merge) returns
  the identical row set and ordering as the previous single OR query.
- Entity routing still returns exact matches only (no substring collisions),
  skips invalid-JSON rows, and keeps RISK-ranked suspicious ordering.
"""

from __future__ import annotations

import json

from sqlalchemy import Text, and_, func, or_, select, text
from sqlalchemy.dialects import sqlite as sqlite_dialect
from sqlalchemy.orm import selectinload

from app.database.database import ensure_retrieval_indexes
from app.models.case import Case
from app.models.memory_dump import MemoryDump
from app.models.plugin_execution import PluginExecution
from app.models.plugin_result import PluginResult
from app.services.forensic_evidence_retrieval_service import (
    ForensicEvidenceRetrievalService,
    _PROCESS_BEARING_TYPES,
    forensic_evidence_retrieval_service,
)

_RETRIEVAL_INDEX_NAMES = (
    "ix_plugin_results_artifact_type",
    "ix_plugin_results_json_pid",
    "ix_plugin_results_json_processid",
    "ix_plugin_results_json_tid",
    "ix_plugin_results_json_threadid",
    "ix_plugin_results_json_thread",
    "ix_plugin_results_json_handlevalue",
    "ix_plugin_results_json_type",
    "ix_plugin_results_json_imagefilename",
    "ix_plugin_results_json_process",
    "ix_plugin_results_json_owner",
    "ix_plugin_results_json_name",
)

_SERVICE = ForensicEvidenceRetrievalService()


# ==============================================================================
# Seeding helpers
# ==============================================================================


def _seed_investigation(
    session,
    investigation_id: str,
    records,
) -> None:
    """Create a Case + MemoryDump + PluginExecutions + PluginResults.

    ``records`` are ``(plugin, artifact_type, artifact_value, risk_level)``
    tuples where ``artifact_value`` is persisted verbatim (so non-JSON rows
    can be injected to exercise the ``json_valid`` guard).
    """

    case = Case(
        case_name=investigation_id,
        investigator="tester",
        description="test",
    )
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

    executions: dict[str, PluginExecution] = {}

    for plugin, artifact_type, artifact_value, risk_level in records:
        if plugin not in executions:
            execution = PluginExecution(
                memory_dump_id=dump.id,
                plugin_name=plugin,
                execution_status="completed",
            )
            session.add(execution)
            session.flush()
            executions[plugin] = execution

        session.add(
            PluginResult(
                plugin_execution_id=executions[plugin].id,
                artifact_type=artifact_type,
                artifact_name=plugin,
                artifact_value=str(artifact_value)[:5000],
                confidence_score=100,
                risk_level=risk_level,
            )
        )

    session.commit()


def _json_record(attributes) -> str:
    """Render attributes as a JSON string for a JSON artifact row."""
    return json.dumps(attributes, default=str)


# ==============================================================================
# Index creation
# ==============================================================================


def test_retrieval_indexes_created_and_idempotent(engine, session):
    _seed_investigation(session, "INV-IDX", [])

    ensure_retrieval_indexes(engine)

    with engine.connect() as connection:
        existing = {
            row[0]
            for row in connection.execute(
                text(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'index'"
                )
            )
        }

    assert set(_RETRIEVAL_INDEX_NAMES) <= existing

    # A second pass must not raise or duplicate any index.
    ensure_retrieval_indexes(engine)

    with engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'index' "
                "AND name IN ("
                + ",".join(f"'{name}'" for name in _RETRIEVAL_INDEX_NAMES)
                + ")"
            )
        ).fetchall()

    assert len(rows) == len(_RETRIEVAL_INDEX_NAMES)


def test_indexes_build_with_free_text_rows(engine, session):
    """Index maintenance must never raise on non-JSON artifact rows."""

    _seed_investigation(
        session,
        "INV-FREETEXT",
        [
            ("windows.pslist", "pslist",
             _json_record({"pid": 1944, "name": "explorer.exe"}), "low"),
            ("windows.info", "info",
             "System Information Image: free text, NOT JSON {{ bad", "low"),
        ],
    )

    ensure_retrieval_indexes(engine)

    matches = forensic_evidence_retrieval_service.retrieve(
        session,
        "INV-FREETEXT",
        "What is process 1944 doing?",
        top_k=10,
    )

    assert matches
    assert all(
        match["metadata"]["artifact_type"] != "info"
        for match in matches
    )


# ==============================================================================
# Query plans (index seeks)
# ==============================================================================


def _plan(session, statement):
    sql = str(
        statement.compile(
            dialect=sqlite_dialect.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )
    return session.connection().exec_driver_sql(
        "EXPLAIN QUERY PLAN " + sql
    ).fetchall()


def _pid_statement(investigation_id: str, pid: str):
    """Build the exact-entity pid query exactly as ``_fetch_pid`` emits it."""
    return (
        select(PluginResult)
        .options(selectinload(PluginResult.plugin_execution))
        .where(ForensicEvidenceRetrievalService._json_valid())
        .where(
            or_(
                ForensicEvidenceRetrievalService._json_text("$.pid") == pid,
                ForensicEvidenceRetrievalService._json_text("$.processid")
                == pid,
            )
        )
        .where(
            ForensicEvidenceRetrievalService._scope_exists(investigation_id)
        )
        .order_by(PluginResult.id.asc())
        .limit(10)
    )


def test_pid_lookup_uses_expression_indexes(engine, session):
    _seed_investigation(
        session,
        "INV-PLAN-PID",
        [
            ("windows.pslist", "pslist",
             _json_record({"pid": 1234, "name": "notepad.exe"}), "low"),
            ("windows.pslist", "pslist",
             _json_record({"processid": 1234, "name": "cmd.exe"}), "low"),
        ],
    )
    ensure_retrieval_indexes(engine)

    statement = _pid_statement("INV-PLAN-PID", "1234")

    plan_rows = _plan(session, statement)
    plan_text = "\n".join(row[3] for row in plan_rows)

    assert "MULTI-INDEX OR" in plan_text
    assert "USING INDEX ix_plugin_results_json_pid" in plan_text
    assert "USING INDEX ix_plugin_results_json_processid" in plan_text


def _tid_statement(investigation_id: str, tid: str):
    """Build the exact-entity tid query exactly as ``_fetch_tid`` emits it."""
    return (
        select(PluginResult)
        .options(selectinload(PluginResult.plugin_execution))
        .where(ForensicEvidenceRetrievalService._json_valid())
        .where(
            or_(
                ForensicEvidenceRetrievalService._json_text("$.tid") == tid,
                ForensicEvidenceRetrievalService._json_text("$.threadid")
                == tid,
                ForensicEvidenceRetrievalService._json_text("$.thread")
                == tid,
                and_(
                    func.lower(
                        ForensicEvidenceRetrievalService._json_text("$.type")
                    )
                    == "thread",
                    ForensicEvidenceRetrievalService._json_text(
                        "$.handlevalue"
                    )
                    == tid,
                ),
            )
        )
        .where(
            ForensicEvidenceRetrievalService._scope_exists(investigation_id)
        )
        .order_by(PluginResult.id.asc())
        .limit(10)
    )


def test_tid_lookup_uses_expression_indexes(engine, session):
    _seed_investigation(
        session,
        "INV-PLAN-TID",
        [
            ("windows.threads", "threads",
             _json_record({"tid": 999, "type": "Thread", "handlevalue": 888}),
             "low"),
            ("windows.handles", "handles",
             _json_record({"pid": 100, "type": "Thread", "handlevalue": 999}),
             "low"),
        ],
    )
    ensure_retrieval_indexes(engine)

    statement = _tid_statement("INV-PLAN-TID", "999")

    plan_rows = _plan(session, statement)
    plan_text = "\n".join(row[3] for row in plan_rows)

    assert "MULTI-INDEX OR" in plan_text
    assert "USING INDEX ix_plugin_results_json_tid" in plan_text


def _name_statement(investigation_id: str, name: str):
    """Build the exact-match process-name query as ``_fetch_process_names``."""
    return (
        select(PluginResult)
        .options(selectinload(PluginResult.plugin_execution))
        .where(
            PluginResult.artifact_type.in_(_PROCESS_BEARING_TYPES),
            ForensicEvidenceRetrievalService._json_valid(),
            or_(
                func.lower(
                    ForensicEvidenceRetrievalService._json_text(
                        "$.imagefilename"
                    )
                )
                == name,
                func.lower(
                    ForensicEvidenceRetrievalService._json_text("$.process")
                )
                == name,
                func.lower(
                    ForensicEvidenceRetrievalService._json_text("$.owner")
                )
                == name,
                func.lower(
                    ForensicEvidenceRetrievalService._json_text("$.name")
                )
                == name,
            ),
            ForensicEvidenceRetrievalService._scope_exists(investigation_id),
        )
        .order_by(PluginResult.id.asc())
        .limit(10)
    )


def test_process_name_lookup_uses_expression_indexes(engine, session):
    _seed_investigation(
        session,
        "INV-PLAN-NAME",
        [
            ("windows.pslist", "pslist",
             _json_record({"pid": 10, "name": "notepad.exe"}), "low"),
            ("windows.pslist", "pslist",
             _json_record({"pid": 11, "imagefilename": "notepad.exe"}), "low"),
        ],
    )
    ensure_retrieval_indexes(engine)

    statement = _name_statement("INV-PLAN-NAME", "notepad.exe")

    plan_rows = _plan(session, statement)
    plan_text = "\n".join(row[3] for row in plan_rows)

    assert "MULTI-INDEX OR" in plan_text
    assert "USING INDEX ix_plugin_results_json_name" in plan_text
    assert "USING INDEX ix_plugin_results_json_imagefilename" in plan_text


# ==============================================================================
# Behavioural equivalence with the pre-index single OR query
# ==============================================================================


def _old_json_text(path: str):
    """Replicate the pre-Phase-5 unguarded ``CAST(json_extract(...) AS TEXT)``."""
    return func.cast(
        func.json_extract(PluginResult.artifact_value, path),
        Text,
    )


def _old_process_name_statement(
    session,
    investigation_id: str,
    names: list[str],
    limit: int,
):
    """Replicate the pre-Phase-5 single OR process-name query exactly."""

    lowered_value = func.lower(PluginResult.artifact_value)

    conditions: list = []

    for name in names:
        escaped = name.replace("%", r"\%").replace("_", r"\_")
        conditions.extend(
            [
                func.lower(_old_json_text("$.imagefilename")) == name,
                func.lower(_old_json_text("$.process")) == name,
                func.lower(_old_json_text("$.owner")) == name,
                func.lower(_old_json_text("$.name")) == name,
                lowered_value.like(
                    f"%{escaped}%",
                    escape="\\",
                ),
            ]
        )

    return (
        select(PluginResult)
        .options(selectinload(PluginResult.plugin_execution))
        .join(
            PluginExecution,
            PluginResult.plugin_execution_id == PluginExecution.id,
        )
        .join(
            MemoryDump,
            PluginExecution.memory_dump_id == MemoryDump.id,
        )
        .where(MemoryDump.investigation_id == investigation_id)
        .where(
            PluginResult.artifact_type.in_(_PROCESS_BEARING_TYPES)
        )
        .where(func.json_valid(PluginResult.artifact_value))
        .where(or_(*conditions))
        .order_by(PluginResult.id.asc())
        .limit(limit)
    )


def test_process_name_split_matches_single_or_query(engine, session):
    """
    The exact-match (indexed) + LIKE (bounded) split must reproduce the
    previous single-OR query result, including LIKE-only rows, ordering by
    id, and exclusion of non-JSON rows — with the acceleration indexes live.
    """

    _seed_investigation(
        session,
        "INV-EQV",
        [
            # LIKE-only match with the LOWEST ids (would be truncated if the
            # split lost them).
            ("windows.pslist", "pslist",
             _json_record({
                 "pid": 1,
                 "name": "svchost.exe",
                 "path": "C:\\Users\\Public\\malware.exe",
             }), "low"),
            ("windows.cmdline", "cmdline",
             _json_record({
                 "pid": 2,
                 "process": "rundll32.exe",
                 "cmd": "C:\\Temp\\malware.exe -enc xyz",
             }), "low"),
            # Non-JSON row whose text mentions malware.exe: must be excluded.
            ("windows.info", "info",
             "System Information Image: malware.exe free text NOT JSON {",
             "low"),
            # Exact JSON matches interleaved by id.
            ("windows.pslist", "pslist",
             _json_record({"pid": 10, "name": "malware.exe"}), "low"),
            ("windows.pstree", "pstree",
             _json_record({"pid": 11, "imagefilename": "malware.exe"}), "low"),
            ("windows.cmdline", "cmdline",
             _json_record({"pid": 12, "process": "malware.exe"}), "low"),
            ("windows.handles", "handles",
             _json_record({"pid": 13, "owner": "malware.exe"}), "low"),
        ],
    )
    ensure_retrieval_indexes(engine)

    limit = 2000

    expected_ids = [
        row.id
        for row in session.scalars(
            _old_process_name_statement(
                session, "INV-EQV", ["malware.exe"], limit
            )
        ).all()
    ]

    matches = forensic_evidence_retrieval_service.retrieve(
        session,
        "INV-EQV",
        "Tell me about malware.exe",
        top_k=limit,
    )

    actual_ids = [match["metadata"]["evidence_id"] for match in matches]

    assert actual_ids == expected_ids
    assert 1 in actual_ids  # LIKE-only row preserved (id 1, low risk)
    assert 2 in actual_ids  # LIKE-only row preserved (id 2)
    assert 7 in actual_ids  # exact owner match (7th seeded record)
    # The non-JSON info row is never included.
    info_row = next(
        row
        for row in session.query(PluginResult).filter_by(
            artifact_type="info"
        ).all()
    )
    assert info_row.id not in actual_ids


# ==============================================================================
# Semantic contracts preserved with indexes present
# ==============================================================================


def test_pid_route_still_exact_only_with_indexes(session):
    _seed_investigation(
        session,
        "INV-IDX-PID",
        [
            ("windows.pslist", "pslist",
             _json_record({"pid": 100, "name": "explorer.exe"}), "low"),
            ("windows.pslist", "pslist",
             _json_record({"pid": 1020, "name": "svchost.exe"}), "low"),
            ("windows.pslist", "pslist",
             _json_record({"pid": 5555, "name": "malware.exe"}), "high"),
        ],
    )

    matches = _SERVICE.retrieve(
        session, "INV-IDX-PID", "What is process 100 doing?", top_k=10
    )

    pids = {
        json.loads(
            session.get(
                PluginResult,
                match["metadata"]["evidence_id"],
            ).artifact_value
        ).get("pid")
        for match in matches
    }

    # No substring collisions with 1020/5555 despite the indexes.
    assert pids == {100}


def test_suspicious_route_risk_ordering_with_indexes(session):
    _seed_investigation(
        session,
        "INV-IDX-RISK",
        [
            ("windows.pslist", "pslist",
             _json_record({"pid": 5555, "name": "malware.exe"}), "high"),
            ("windows.netscan", "netscan",
             _json_record({
                 "pid": 100,
                 "localaddr": "0.0.0.0",
                 "foreignaddr": "10.0.0.5",
                 "foreignport": 4444,
                 "state": "ESTABLISHED",
             }), "medium"),
            ("windows.handles", "handles",
             _json_record({"pid": 100, "type": "Thread", "handlevalue": 321}),
             "low"),
        ],
    )

    matches = _SERVICE.retrieve(
        session,
        "INV-IDX-RISK",
        "Are there any suspicious processes?",
        top_k=10,
    )

    risk_levels = [
        session.get(
            PluginResult,
            match["metadata"]["evidence_id"],
        ).risk_level
        for match in matches
    ]

    assert risk_levels[0] == "high"
    assert all(level in {"high", "medium"} for level in risk_levels)


def test_large_corpus_process_name_query_correct(session):
    """
    A multi-thousand-row corpus must still return exact matches only via the
    indexed path (no scan of unrelated PIDs), keeping the fallback fast.
    """

    records = [
        ("windows.pslist", "pslist",
         _json_record({"pid": i, "name": f"process_{i}.exe"}), "low")
        for i in range(3000)
    ]
    records.append(
        ("windows.pslist", "pslist",
         _json_record({"pid": 9999, "name": "target.exe"}), "high")
    )
    records.append(
        ("windows.info", "info",
         "free text target.exe NOT JSON {", "low")
    )
    _seed_investigation(session, "INV-LARGE", records)

    matches = _SERVICE.retrieve(
        session,
        "INV-LARGE",
        "Tell me about target.exe",
        top_k=10,
    )

    assert matches
    ids = [match["metadata"]["evidence_id"] for match in matches]
    target_id = next(
        row.id
        for row in session.query(PluginResult).filter_by(
            artifact_type="pslist"
        ).all()
        if "target.exe" in json.loads(row.artifact_value).get("name", "")
    )
    assert ids == [target_id]
