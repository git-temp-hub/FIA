"""
Regression tests for the SQLite-authoritative chat evidence fallback.

The production bug: when ChromaDB was empty but ``plugin_results`` contained
evidence, the assistant falsely answered "No indexed evidence was found".
SQLite is authoritative — zero vectors must never mean zero evidence.

Covered
-------
- Entity-first routing (PID, thread/TID, process name, suspicious, artifacts).
- Bounded SQL filtering with exact ``json_extract`` matching (no substring
  PID collisions, no full-dump loads).
- Orchestration: Chroma empty + SQLite evidence -> fallback answer;
  Chroma exception -> graceful fallback; empty everywhere -> revised copy.
- Weak (< SEMANTIC_QUALITY_FLOOR) or irrelevant Chroma hits never shadow the
  authoritative SQLite suspicious/entity pass.
- No-hallucination: an absent entity produces "cannot be determined" without
  calling the LLM.
"""

from __future__ import annotations

import json

from app.database.repositories import PluginResultRepository
from app.llm.prompt_builder import PromptBuilder
from app.llm.response_parser import ResponseParser
from app.models.case import Case
from app.models.memory_dump import MemoryDump
from app.models.plugin_execution import PluginExecution
from app.models.plugin_result import PluginResult
from app.services.forensic_evidence_retrieval_service import (
    ForensicEvidenceRetrievalService,
    NO_EVIDENCE_COPY,
    NO_MATCH_COPY,
    answer_with_evidence_fallback,
    build_evidence_document,
    detect_query_intent,
    forensic_evidence_retrieval_service,
)

# ==============================================================================
# Seeding helpers
# ==============================================================================


def _seed_investigation(
    session,
    investigation_id: str,
    records,
) -> None:
    """Create a Case + MemoryDump + PluginExecutions + PluginResults."""

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

    for plugin, artifact_type, attributes, risk_level in records:
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
                artifact_value=json.dumps(
                    attributes,
                    default=str,
                )[:5000],
                confidence_score=100,
                risk_level=risk_level,
            )
        )

    session.commit()


DEFAULT_RECORDS = [
    ("windows.pslist", "pslist",
     {"pid": 100, "name": "explorer.exe", "path": "C:\\Windows"}, "low"),
    ("windows.pslist", "pslist",
     {"pid": 1020, "name": "svchost.exe", "path": "C:\\Windows\\System32"},
     "low"),
    ("windows.pslist", "pslist",
     {"pid": 5555, "name": "malware.exe", "path": "C:\\Temp\\malware"},
     "high"),
    ("windows.cmdline", "cmdline",
     {"pid": 5555, "cmd": "C:\\Temp\\malware.exe --connect 10.0.0.5:4444"},
     "high"),
    ("windows.handles", "handles",
     {"pid": 100, "type": "Thread", "handlevalue": 321, "name": ""}, "low"),
    ("windows.netscan", "netscan",
     {"pid": 100, "localaddr": "0.0.0.0", "localport": 49152,
      "foreignaddr": "10.0.0.5", "foreignport": 4444,
      "state": "ESTABLISHED"},
     "medium"),
]

_PROMPT_BUILDER = PromptBuilder()
_PARSER = ResponseParser()


def _fake_llm(prompt: str) -> str:
    return (
        "The evidence shows the process was present during acquisition "
        "and its command line was recorded. [1]\nCONFIDENCE: 90"
    )


def _orchestrate(
    *,
    investigation_id: str,
    question: str,
    top_k: int = 6,
    db=None,
    semantic=None,
    count=None,
    fallback=None,
    llm=None,
    lazy=None,
):
    if semantic is None:
        semantic = lambda _q, _k: []  # noqa: E731
    if count is None:
        count = lambda: 0  # noqa: E731
    if fallback is None:
        fallback = lambda _q, _k: []  # noqa: E731
    if llm is None:
        llm = _fake_llm
    if lazy is None:
        lazy = lambda: None  # noqa: E731

    return answer_with_evidence_fallback(
        investigation_id=investigation_id,
        question=question,
        top_k=top_k,
        db=db,
        semantic_search=semantic,
        count_evidence=count,
        fallback_retrieve=fallback,
        llm_generate=llm,
        prompt_builder=_PROMPT_BUILDER,
        response_parser=_PARSER,
        lazy_index=lazy,
    )


# ==============================================================================
# Entity detection (pure)
# ==============================================================================


def test_detect_pid_tid_and_process_names():
    intent = detect_query_intent("What is process 100 doing?")
    assert intent.pid == "100"

    intent = detect_query_intent("Show pid 1020 details")
    assert intent.pid == "1020"

    intent = detect_query_intent("Which thread is tid 321?")
    assert intent.tid == "321"

    intent = detect_query_intent("Tell me about malware.exe")
    assert "malware.exe" in intent.process_names


def test_detect_suspicious_and_keyword_artifacts():
    intent = detect_query_intent("Are there any suspicious processes?")
    assert intent.suspicious is True
    assert "pslist" in (intent.artifact_types or ())

    intent = detect_query_intent("Which network connections exist?")
    assert intent.artifact_types == ("netscan",)

    intent = detect_query_intent("Show me the registry keys")
    assert "printkey" in (intent.artifact_types or ())


def test_detect_no_entities_for_generic_question():
    intent = detect_query_intent("What is going on in this system?")
    assert intent.pid is None
    assert intent.tid is None
    assert not intent.process_names
    assert intent.suspicious is False
    assert intent.artifact_types is None


# ==============================================================================
# Evidence document building
# ==============================================================================


def test_build_evidence_document_ignores_pstree_children():
    document = build_evidence_document(
        "windows.pstree",
        "pstree",
        json.dumps({
            "pid": 4321,
            "imagefilename": "cmd.exe",
            "__children": [{"pid": 4322, "imagefilename": "nested.exe"}],
        }),
    )

    assert "cmd.exe" in document
    assert "children" not in document
    assert document.count("\n") >= 3


# ==============================================================================
# Repository count
# ==============================================================================


def test_count_by_investigation_is_authoritative(session):
    _seed_investigation(session, "INV-COUNT", DEFAULT_RECORDS)

    repository = PluginResultRepository(session)

    assert repository.count_by_investigation("INV-COUNT") == len(
        DEFAULT_RECORDS
    )
    assert repository.count_by_investigation("INV-OTHER") == 0


# ==============================================================================
# Deterministic routing (real SQLite session)
# ==============================================================================


def test_pid_route_returns_exact_matches_only(session):
    _seed_investigation(session, "INV-PID", DEFAULT_RECORDS)

    matches = forensic_evidence_retrieval_service.retrieve(
        session,
        "INV-PID",
        "What is process 100 doing?",
        top_k=10,
    )

    assert matches

    pids = {
        json.loads(
            session.get(
                PluginResult,
                match["metadata"]["evidence_id"],
            ).artifact_value
        ).get("pid")
        for match in matches
    }

    # json_extract exact match: no substring collisions with 1020/5555.
    assert pids == {100}

    # pid 1020/question route must never drift into other PIDs.
    matches_1020 = forensic_evidence_retrieval_service.retrieve(
        session,
        "INV-PID",
        "Show pid 1020 details",
        top_k=10,
    )
    assert matches_1020

    pids_1020 = {
        json.loads(
            session.get(
                PluginResult,
                match["metadata"]["evidence_id"],
            ).artifact_value
        ).get("pid")
        for match in matches_1020
    }
    assert pids_1020 == {1020}


def test_unknown_pid_returns_no_matches(session):
    _seed_investigation(session, "INV-UNKNOWN", DEFAULT_RECORDS)

    matches = forensic_evidence_retrieval_service.retrieve(
        session,
        "INV-UNKNOWN",
        "What is PID 999 doing?",
        top_k=10,
    )

    assert matches == []


def test_thread_route_returns_thread_records(session):
    _seed_investigation(session, "INV-THREAD", DEFAULT_RECORDS)

    matches = forensic_evidence_retrieval_service.retrieve(
        session,
        "INV-THREAD",
        "Which thread is tid 321?",
        top_k=10,
    )

    assert matches
    assert all(
        match["metadata"]["artifact_type"] == "handles"
        for match in matches
    )


def test_process_name_route_bounds_evidence(session):
    _seed_investigation(session, "INV-NAME", DEFAULT_RECORDS)

    matches = forensic_evidence_retrieval_service.retrieve(
        session,
        "INV-NAME",
        "Tell me about malware.exe",
        top_k=10,
    )

    assert matches
    assert all(
        "malware.exe"
        in session.get(
            PluginResult,
            match["metadata"]["evidence_id"],
        ).artifact_value
        for match in matches
    )


def test_suspicious_route_prefers_high_risk(session):
    _seed_investigation(session, "INV-RISK", DEFAULT_RECORDS)

    matches = forensic_evidence_retrieval_service.retrieve(
        session,
        "INV-RISK",
        "Are there any suspicious processes?",
        top_k=10,
    )

    assert matches
    risk_levels = [
        session.get(
            PluginResult,
            match["metadata"]["evidence_id"],
        ).risk_level
        for match in matches
    ]

    # HIGH-first ordering, and never LOW/None noise when risk exists.
    assert risk_levels[0] == "high"
    assert all(level in {"high", "medium"} for level in risk_levels)


def test_network_route_returns_netscan_only(session):
    _seed_investigation(session, "INV-NET", DEFAULT_RECORDS)

    matches = forensic_evidence_retrieval_service.retrieve(
        session,
        "INV-NET",
        "Which network connections exist?",
        top_k=10,
    )

    assert matches
    assert all(
        match["metadata"]["artifact_type"] == "netscan"
        for match in matches
    )


def test_generic_route_returns_grounded_sample(session):
    _seed_investigation(session, "INV-GENERIC", DEFAULT_RECORDS)

    matches = forensic_evidence_retrieval_service.retrieve(
        session,
        "INV-GENERIC",
        "What is going on in this system?",
        top_k=6,
    )

    assert matches
    assert all(
        "INV-GENERIC" == match["metadata"]["investigation_id"]
        for match in matches
    )


def test_empty_investigation_returns_empty(session):
    _seed_investigation(session, "INV-EMPTY", [])

    matches = forensic_evidence_retrieval_service.retrieve(
        session,
        "INV-EMPTY",
        "What processes are running?",
        top_k=6,
    )

    assert matches == []


# ==============================================================================
# Orchestration: Chroma empty / SQLite authoritative
# ==============================================================================


def test_no_vectors_but_evidence_answers_from_fallback(
    session,
    monkeypatch,
):
    """The core bug: Chroma empty + SQLite evidence must answer, not 'no index'."""

    _seed_investigation(session, "INV-BUG", DEFAULT_RECORDS)
    repository = PluginResultRepository(session)
    service = ForensicEvidenceRetrievalService()

    lazy_calls = []

    result = _orchestrate(
        investigation_id="INV-BUG",
        question="What is process 100 doing?",
        top_k=6,
        db=session,
        semantic=lambda _q, _k: [],
        count=lambda: repository.count_by_investigation("INV-BUG"),
        fallback=lambda q, k: service.retrieve(
            session, "INV-BUG", q, k
        ),
        lazy=lambda: lazy_calls.append(True),
    )

    assert result["insufficient"] is False
    assert result["references"]
    assert result["answer"]
    assert lazy_calls == [True]

    # References must expose the rich evidence identity.
    reference = result["references"][0]
    assert reference["evidence_id"] is not None
    assert reference["plugin_name"]
    assert reference["artifact_type"]
    assert reference["document"]


def test_zero_vectors_and_zero_evidence_uses_revised_copy(session):
    """Truly empty investigation returns the new wording, not the old one."""

    _seed_investigation(session, "INV-NODATA", [])

    llm_called = []
    lazy_called = []

    result = _orchestrate(
        investigation_id="INV-NODATA",
        question="Which processes ran?",
        top_k=6,
        db=session,
        semantic=lambda _q, _k: [],
        count=lambda: 0,
        fallback=lambda _q, _k: [],
        llm=lambda p: llm_called.append(p) or "",
        lazy=lambda: lazy_called.append(True),
    )

    assert result["insufficient"] is True
    assert result["answer"] == NO_EVIDENCE_COPY
    assert result["references"] == []
    assert "indexed evidence" not in result["answer"]
    assert llm_called == []
    assert lazy_called == []


def test_chroma_exception_falls_back_to_sqlite(session):
    _seed_investigation(session, "INV-EXC", DEFAULT_RECORDS)
    service = ForensicEvidenceRetrievalService()

    def broken_semantic(_q, _k):
        raise RuntimeError("chroma unavailable")

    result = _orchestrate(
        investigation_id="INV-EXC",
        question="What is going on in this system?",
        top_k=6,
        db=session,
        semantic=broken_semantic,
        count=lambda: 5,
        fallback=lambda q, k: service.retrieve(session, "INV-EXC", q, k),
    )

    assert result["insufficient"] is False
    assert result["references"]
    assert result["answer"]


def test_partial_vectors_use_semantic_path_without_fallback(session):
    """When Chroma has matches, the SQLite fallback and lazy index stay off."""

    semantic_match = {
        "id": "ev-1",
        "document": "imagefilename: svchost.exe",
        "metadata": {
            "investigation_id": "INV-SEM",
            "plugin_name": "windows.pslist",
            "artifact_type": "pslist",
            "evidence_id": 1,
            "confidence_score": 100,
        },
        "distance": 0.1,
        "score": 0.909,
    }

    fallback_called = []
    lazy_called = []

    result = _orchestrate(
        investigation_id="INV-SEM",
        question="What is going on in this system?",
        top_k=6,
        db=session,
        semantic=lambda _q, _k: [semantic_match],
        count=lambda: 42,
        fallback=lambda _q, _k: fallback_called.append(True) or [],
        lazy=lambda: lazy_called.append(True),
    )

    assert result["references"]
    assert result["references"][0]["evidence_id"] == 1
    assert fallback_called == []
    assert lazy_called == []


def test_absent_entity_does_not_hallucinate(session):
    """Evidence exists, but the requested entity is absent: no fabrication."""

    _seed_investigation(session, "INV-HALL", DEFAULT_RECORDS)
    service = ForensicEvidenceRetrievalService()

    llm_called = []

    result = _orchestrate(
        investigation_id="INV-HALL",
        question="What did PID 9999 do on this host?",
        top_k=6,
        db=session,
        semantic=lambda _q, _k: [],
        count=lambda: 6,
        fallback=lambda q, k: service.retrieve(session, "INV-HALL", q, k),
        llm=lambda p: llm_called.append(p) or "fabricated",
    )

    assert result["insufficient"] is True
    assert result["answer"] == NO_MATCH_COPY
    assert result["references"] == []
    assert llm_called == []


def test_lazy_index_failure_does_not_break_fallback_answer(session):
    _seed_investigation(session, "INV-LAZY", DEFAULT_RECORDS)
    service = ForensicEvidenceRetrievalService()

    def broken_lazy():
        raise RuntimeError("vector store down")

    result = _orchestrate(
        investigation_id="INV-LAZY",
        question="Which processes are running?",
        top_k=6,
        db=session,
        semantic=lambda _q, _k: [],
        count=lambda: 6,
        fallback=lambda q, k: service.retrieve(session, "INV-LAZY", q, k),
        lazy=broken_lazy,
    )

    # The answer must still be produced despite the failed lazy index.
    assert result["insufficient"] is False
    assert result["references"]


def test_old_canned_no_indexed_evidence_wording_is_eliminated():
    """The historical false-negative sentence must no longer be emitted."""

    assert "No indexed evidence was found" not in NO_EVIDENCE_COPY
    assert "No indexed evidence was found" not in NO_MATCH_COPY


# ==============================================================================
# Phase-12 regression: weak Chroma must never shadow authoritative SQLite
# ==============================================================================


def test_weak_semantic_falls_back_to_sqlite_instead_of_weak_refs(session):
    """
    The reported bug: Chroma returned a few unrelated `handles` rows at
    score ~0.38 for "list all suspicious processes", and the orchestrator
    answered from those weak references instead of SQLite's HIGH/MEDIUM
    records. A weak (< SEMANTIC_QUALITY_FLOOR) free-form hit must fall back
    to SQLite rather than mislead the LLM.
    """

    _seed_investigation(session, "INV-WEAK", DEFAULT_RECORDS)
    service = ForensicEvidenceRetrievalService()

    weak_match = {
        "id": "ev-9999",
        "document": "type: Thread handlevalue: 5",
        "metadata": {
            "investigation_id": "INV-WEAK",
            "plugin_name": "windows.handles",
            "artifact_type": "handles",
            "evidence_id": 9999,
            "confidence_score": 100,
        },
        "distance": 0.62,
        "score": 0.38,
    }

    result = _orchestrate(
        investigation_id="INV-WEAK",
        question="What is the overall state of the system?",
        top_k=6,
        db=session,
        semantic=lambda _q, _k: [weak_match],
        count=lambda: 6,
        fallback=lambda q, k: service.retrieve(session, "INV-WEAK", q, k),
    )

    assert result["references"]
    # The weak synthetic evidence_id must not be trusted over real SQLite.
    assert result["references"][0]["evidence_id"] != 9999
    assert result["references"][0]["evidence_id"] is not None


def test_structured_suspicious_ignores_irrelevant_chroma(session):
    """
    "list all suspicious processes" is a structured intent and must answer
    from SQLite's suspicious pass, even though Chroma holds weak, unrelated
    matches. This is the literal production scenario.
    """

    _seed_investigation(session, "INV-SUSP", DEFAULT_RECORDS)
    service = ForensicEvidenceRetrievalService()

    chroma_called = []

    result = _orchestrate(
        investigation_id="INV-SUSP",
        question="List all suspicious processes",
        top_k=6,
        db=session,
        semantic=lambda _q, _k: chroma_called.append(True) or [
            {
                "id": "ev-0",
                "document": "type: Thread handlevalue: 7",
                "metadata": {"artifact_type": "handles", "evidence_id": 0},
                "score": 0.38,
            }
        ],
        count=lambda: 7,
        fallback=lambda q, k: service.retrieve(session, "INV-SUSP", q, k),
    )

    # Structured path never consults Chroma; it answers from SQLite.
    assert chroma_called == []
    assert result["references"]
    assert result["references"][0]["risk_level"] == "high"


def test_null_risk_level_still_flagged_suspicious(session):
    """
    Old investigations carry NULL ``risk_level``. Suspicious detection must
    rely on derived indicators (encoded commands, paths, ports), not the
    NULL classification.
    """

    null_records = [
        ("windows.pslist", "pslist",
         {"pid": 700, "name": "powershell.exe",
          "path": "C:\\Windows\\System32"}, None),
        ("windows.cmdline", "cmdline",
         {"pid": 700, "process": "powershell.exe",
          "cmd": "powershell.exe -enc SQBFAFgAOgBBAGwAbABvAHcATABvAGEAbgBEAGwAbwBhAGQAUwB0AHIAaQBuAGcA"},
         None),
    ]
    _seed_investigation(session, "INV-NULL", null_records)
    service = ForensicEvidenceRetrievalService()

    matches = service.retrieve(
        session,
        "INV-NULL",
        "Are there any suspicious processes?",
        top_k=10,
    )

    assert matches
    flagged = [
        match
        for match in matches
        if "injected-memory-region" in (match["metadata"].get("suspicious_flags") or [])
        or "suspicious-command" in (match["metadata"].get("suspicious_flags") or [])
        or "executable-in-suspicious-location" in (match["metadata"].get("suspicious_flags") or [])
    ]
    assert flagged


def test_prompt_contains_retrieved_evidence(session):
    """The LLM prompt must embed the actual evidence, enabling citations."""

    _seed_investigation(session, "INV-PROMPT", DEFAULT_RECORDS)
    service = ForensicEvidenceRetrievalService()
    seen_prompts = []

    result = _orchestrate(
        investigation_id="INV-PROMPT",
        question="What is process 1020 doing?",
        top_k=6,
        db=session,
        semantic=lambda _q, _k: [],
        count=lambda: 6,
        fallback=lambda q, k: service.retrieve(session, "INV-PROMPT", q, k),
        llm=lambda p: seen_prompts.append(p)
        or "The process svchost.exe was present. [1]\nCONFIDENCE: 90",
    )

    assert result["answer"]
    assert seen_prompts
    # Evidence document lines are numbered and embedded in the prompt.
    assert "[1]" in seen_prompts[0]
    assert "imagefilename" in seen_prompts[0] or "svchost.exe" in seen_prompts[0]


def test_evidence_citations_map_to_real_references(session):
    """Citations must resolve to actual provided evidence ids."""

    _seed_investigation(session, "INV-CITE", DEFAULT_RECORDS)
    service = ForensicEvidenceRetrievalService()

    result = _orchestrate(
        investigation_id="INV-CITE",
        question="Are there any suspicious processes?",
        top_k=6,
        db=session,
        semantic=lambda _q, _k: [],
        count=lambda: 6,
        fallback=lambda q, k: service.retrieve(session, "INV-CITE", q, k),
        llm=lambda p: "malware.exe shows injected memory. [1]\nCONFIDENCE: 88",
    )

    assert result["citations"]
    for citation_reference in result["citations"]:
        assert citation_reference["evidence_id"] is not None
        assert citation_reference in result["references"]


# ==============================================================================
# Phase-13 regression: non-JSON artifact rows must not break JSON routes
# ==============================================================================


def test_non_json_artifact_rows_do_not_break_pid_route(session):
    """
    Real dumps include artifact types (e.g. ``info``) whose persisted value is
    free text, not JSON. ``json_extract`` over the whole investigation then
    raises ``sqlite3.OperationalError: malformed JSON``. Every JSON-path
    predicate must be guarded by ``json_valid``.
    """

    _seed_investigation(
        session,
        "INV-JSON",
        [
            ("windows.pslist", "pslist",
             {"pid": 1944, "name": "explorer.exe",
              "path": "C:\\Windows"}, "low"),
        ],
    )

    # Inject a non-JSON row (as real `info` output is stored).
    from app.models.plugin_execution import PluginExecution
    from app.models.memory_dump import MemoryDump
    from app.models.plugin_result import PluginResult

    dump = session.query(MemoryDump).filter_by(
        investigation_id="INV-JSON"
    ).one()
    execution = PluginExecution(
        memory_dump_id=dump.id,
        plugin_name="windows.info",
        execution_status="completed",
    )
    session.add(execution)
    session.flush()
    session.add(
        PluginResult(
            plugin_execution_id=execution.id,
            artifact_type="info",
            artifact_name="windows.info",
            artifact_value=(
                "System Information Image: Total 4 processes, this line is "
                "free text and NOT valid JSON {{ bad"
            ),
            confidence_score=100,
            risk_level="low",
        )
    )
    session.commit()

    service = ForensicEvidenceRetrievalService()

    # The malformed JSON row must be skipped, not crash the whole query.
    matches = service.retrieve(
        session,
        "INV-JSON",
        "What is process 1944 doing?",
        top_k=10,
    )

    assert matches
    assert all(
        match["metadata"]["artifact_type"] != "info"
        for match in matches
    )
    assert all(
        match["metadata"]["pid"] in ("1944", 1944)
        for match in matches
    )