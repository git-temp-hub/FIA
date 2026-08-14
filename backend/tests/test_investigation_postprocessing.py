"""
Tests for large-investigation post-processing reliability.

Covers:
- RAG indexing splits large evidence sets into bounded batches so no
  single embed/add call exceeds the ChromaDB maximum batch size (5461).
- ``index_investigation`` preserves the investigation_id metadata filter
  and returns consistent indexed/total/removed counts.
- ``classify_investigation_evidence`` commits in bounded batches instead of
  after every record and stays idempotent.
- The route's background post-processing runs indexing before classification
  and logs (rather than raises) when indexing fails.

The heavy ``embedding_manager`` / ``vector_store`` modules are replaced with
lightweight stubs BEFORE ``indexing_service`` is imported so the real
SentenceTransformer model and ChromaDB client are never loaded.
"""

from __future__ import annotations

import json
import math
import asyncio
import sys
import types

from starlette.background import BackgroundTasks


# ==============================================================================
# Lightweight stand-ins for the heavy RAG modules
# ==============================================================================


class _FakeEmbeddingManager:
    """
    Stand-in for ``EmbeddingManager``: builds documents but returns
    dummy fixed-size vectors without loading any model.
    """

    def build_document(self, evidence: dict) -> str:
        return "\n".join(
            f"{key}: {value}"
            for key, value in evidence.items()
            if value is not None
        )

    def embed_documents(
        self,
        documents: list[str],
    ) -> list[list[float]]:
        return [[0.0] * 8 for _ in documents]


class _RecordingVectorStore:
    """
    Stand-in for ``VectorStore`` that records every ``add_documents`` call
    instead of touching ChromaDB.
    """

    def __init__(self) -> None:
        self.added: list[dict] = []
        self.deleted: list[str] = []
        self.delete_calls: int = 0

    def delete_by_metadata(self, where: dict) -> int:
        self.delete_calls += 1
        return 0

    def add_documents(
        self,
        ids: list[str],
        documents: list[str],
        embeddings: list[list[float]],
        metadatas: list[dict],
    ) -> None:
        self.added.append(
            {
                "ids": list(ids),
                "documents": list(documents),
                "embeddings": list(embeddings),
                "metadatas": list(metadatas),
            }
        )

    def upsert_documents(
        self,
        ids: list[str],
        documents: list[str],
        embeddings: list[list[float]],
        metadatas: list[dict],
    ) -> None:
        self.add_documents(
            ids,
            documents,
            embeddings,
            metadatas,
        )

    def delete_documents(self, document_ids: list[str]) -> int:
        self.deleted.extend(document_ids)
        return len(document_ids)


_EMBEDDING_STUB = types.ModuleType(
    "app.services.rag.embedding_manager"
)
_EMBEDDING_STUB.EmbeddingManager = _FakeEmbeddingManager  # type: ignore[attr-defined]

_VECTOR_STUB = types.ModuleType("app.services.rag.vector_store")
_VECTOR_STUB.VectorStore = _RecordingVectorStore  # type: ignore[attr-defined]

sys.modules["app.services.rag.embedding_manager"] = _EMBEDDING_STUB
sys.modules["app.services.rag.vector_store"] = _VECTOR_STUB


# ==============================================================================
# Imports (indexing_service must be imported after the stubs are installed)
# ==============================================================================

import pytest  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.api.routes.investigation import (  # noqa: E402
    _run_evidence_indexing,
    _run_risk_classification,
)
from app.database.repositories import PluginResultRepository  # noqa: E402
from app.models.case import Case  # noqa: E402
from app.models.memory_dump import MemoryDump  # noqa: E402
from app.models.plugin_execution import PluginExecution  # noqa: E402
from app.models.plugin_result import PluginResult  # noqa: E402
from app.services.rag.indexing_service import (  # noqa: E402
    INDEXING_BATCH_SIZE,
    RAGIndexingService,
    rag_indexing_service,
)
from app.services.risk_classification_service import (  # noqa: E402
    CLASSIFICATION_COMMIT_BATCH,
    classify_investigation_evidence,
)
from app.services.investigation_phase_tracker import (  # noqa: E402
    PHASE_COMPLETED,
    PHASE_INDEXING,
    investigation_phase_tracker,
)

# ChromaDB rejects a single batch larger than 5461 documents.
CHROMA_MAX_BATCH_SIZE = 5461


# ==============================================================================
# Helpers
# ==============================================================================


def _seed_evidence_rows(
    session: Session,
    investigation_id: str,
    count: int,
) -> str:
    """Create a completed investigation with ``count`` evidence rows."""

    case = Case(
        case_name=investigation_id,
        investigator="tester",
        description="t",
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

    execution = PluginExecution(
        memory_dump_id=dump.id,
        plugin_name="windows.pslist",
        execution_status="completed",
    )
    session.add(execution)
    session.flush()

    for index in range(count):
        session.add(
            PluginResult(
                plugin_execution_id=execution.id,
                artifact_type="pslist",
                artifact_name="windows.pslist",
                artifact_value=json.dumps(
                    {
                        "pid": 1000 + index,
                        "name": "svchost.exe",
                        "path": "C:\\Windows\\System32",
                    }
                ),
                confidence_score=100,
            )
        )

    session.commit()

    return investigation_id


# ==============================================================================
# Fix 1: RAG indexing batching
# ==============================================================================


def test_index_investigation_splits_large_corpus_into_bounded_batches(session):
    """>5461 evidence rows must be embedded/added in several bounded batches."""

    investigation_id = _seed_evidence_rows(session, "INV-BATCH", 6000)

    vector_store = _RecordingVectorStore()
    service = RAGIndexingService(
        embedding_manager=_FakeEmbeddingManager(),
        vector_store=vector_store,
    )

    result = service.index_investigation(investigation_id, session)

    assert result["indexed"] == 6000
    assert result["total"] == 6000
    assert result["removed"] == 0

    batches = vector_store.added

    # Multiple batches are produced and none exceeds the limits.
    assert len(batches) > 1
    assert len(batches) == math.ceil(6000 / INDEXING_BATCH_SIZE)

    for batch in batches:
        assert len(batch["ids"]) <= INDEXING_BATCH_SIZE
        assert len(batch["ids"]) <= CHROMA_MAX_BATCH_SIZE
        assert (
            len(batch["ids"])
            == len(batch["documents"])
            == len(batch["embeddings"])
            == len(batch["metadatas"])
        )
        for metadata in batch["metadatas"]:
            assert metadata["investigation_id"] == investigation_id

    # Every evidence row is indexed exactly once across the batches.
    indexed_ids = [
        evidence_id
        for batch in batches
        for evidence_id in batch["ids"]
    ]
    assert len(indexed_ids) == 6000
    assert len(set(indexed_ids)) == 6000


def test_index_investigation_single_batch_within_limit(session):
    """Small investigations still index in a single in-limit batch."""

    investigation_id = _seed_evidence_rows(session, "INV-SMALL", 3)

    vector_store = _RecordingVectorStore()
    service = RAGIndexingService(
        embedding_manager=_FakeEmbeddingManager(),
        vector_store=vector_store,
    )

    result = service.index_investigation(investigation_id, session)

    assert result["indexed"] == 3
    assert result["removed"] == 0
    assert len(vector_store.added) == 1
    assert len(vector_store.added[0]["ids"]) == 3
    # Incremental indexing never wipes the investigation's existing vectors.
    assert vector_store.delete_calls == 0
    assert vector_store.deleted == []


# ==============================================================================
# Fix 2: classification batched commits
# ==============================================================================


def test_classify_uses_batched_commits_not_per_row(session, monkeypatch):
    """Classification must commit in bounded batches, not after every record."""

    investigation_id = _seed_evidence_rows(session, "INV-CLASSIFY", 1050)

    commit_count = [0]
    real_commit = session.commit

    def counting_commit(*args, **kwargs):
        commit_count[0] += 1
        return real_commit(*args, **kwargs)

    monkeypatch.setattr(session, "commit", counting_commit)

    updated = classify_investigation_evidence(session, investigation_id)

    assert updated == 1050
    # 1050 / 500 -> two batch commits plus one final commit.
    expected_commits = (
        math.floor(1050 / CLASSIFICATION_COMMIT_BATCH) + 1
    )
    assert commit_count[0] == expected_commits
    assert commit_count[0] < 1050

    repository = PluginResultRepository(session)
    records = repository.get_by_investigation(investigation_id)
    assert all(record.risk_level is not None for record in records)


def test_classify_stays_idempotent_with_batched_commits(session, monkeypatch):
    """Re-running classification must skip already-classified records."""

    investigation_id = _seed_evidence_rows(session, "INV-CLASSIFY-2", 900)

    commit_count = [0]
    real_commit = session.commit

    def counting_commit(*args, **kwargs):
        commit_count[0] += 1
        return real_commit(*args, **kwargs)

    monkeypatch.setattr(session, "commit", counting_commit)

    first = classify_investigation_evidence(session, investigation_id)
    second = classify_investigation_evidence(session, investigation_id)

    assert first == 900
    assert second == 0
    # First pass: 900/500 -> 1 batch commit + 1 final. Second pass: 1 final.
    assert commit_count[0] == 3


# ==============================================================================
# Fix 3: background post-processing (index before classify)
# ==============================================================================


def test_background_post_processing_indexes_then_classifies(session_factory):
    """The route's background tasks must run indexing then classification."""

    investigation_id = _seed_evidence_rows(
        session_factory(),
        "INV-BG",
        25,
    )

    rag_indexing_service.vector_store.added.clear()

    tasks = BackgroundTasks()
    tasks.add_task(
        _run_evidence_indexing,
        investigation_id,
        session_factory,
    )
    tasks.add_task(
        _run_risk_classification,
        investigation_id,
        session_factory,
    )
    asyncio.run(tasks())

    # Indexing ran: vectors were added through the (recording) store.
    batches = rag_indexing_service.vector_store.added
    assert batches
    indexed_total = sum(len(batch["ids"]) for batch in batches)
    assert indexed_total == 25

    # Classification ran afterwards and persisted risk levels.
    with session_factory() as db:
        records = PluginResultRepository(
            db
        ).get_by_investigation(investigation_id)
        assert len(records) == 25
        assert all(record.risk_level is not None for record in records)


def test_background_indexing_failure_is_logged_not_raised(monkeypatch):
    """Indexing failures inside the background task must not propagate."""

    from app.services.rag import indexing_service as indexing_module

    def broken_index(*args, **kwargs):
        raise RuntimeError("chroma unavailable")

    monkeypatch.setattr(
        indexing_module.rag_indexing_service,
        "index_investigation",
        broken_index,
    )

    # Must return None without raising. The indexing phase is still reported.
    assert (
        _run_evidence_indexing("INV-X", session_factory=lambda: None)
        is None
    )
    assert investigation_phase_tracker.get("INV-X") == PHASE_INDEXING
    investigation_phase_tracker.clear("INV-X")


def test_background_tasks_report_phase_transitions(session_factory):
    """Indexing then classification must expose their phases to status."""

    investigation_id = _seed_evidence_rows(
        session_factory(),
        "INV-BG-PHASE",
        25,
    )

    tasks = BackgroundTasks()
    tasks.add_task(
        _run_evidence_indexing,
        investigation_id,
        session_factory,
    )
    tasks.add_task(
        _run_risk_classification,
        investigation_id,
        session_factory,
    )
    asyncio.run(tasks())

    # After both post-processing passes finish the phase is completed.
    assert investigation_phase_tracker.get(investigation_id) == (
        PHASE_COMPLETED
    )
    investigation_phase_tracker.clear(investigation_id)
