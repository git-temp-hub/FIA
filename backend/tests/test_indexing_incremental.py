"""
Tests for incremental, bounded-memory RAG indexing.

Covers:
- Evidence rows are streamed in bounded pages (never loaded wholesale).
- Re-running indexing on unchanged evidence does zero work (no re-embed).
- New evidence rows added to an investigation are indexed on the next run.
- Changed evidence (different content hash) is re-embedded.
- Stale vectors for deleted evidence rows are removed (SQLite is authoritative).
- Indexing jobs are serialized so one loaded model is never used concurrently.
- The index batch size is configurable (env / settings) and capped.

The heavy ``embedding_manager`` / ``vector_store`` modules are replaced with
lightweight stubs BEFORE ``indexing_service`` is imported so the real
SentenceTransformer model and ChromaDB client are never loaded.
"""

from __future__ import annotations

import json
import math
import sys
import threading
import time
import types

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
    Stand-in for ``VectorStore`` that records every write instead of
    touching ChromaDB.
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


class _ConcurrencyTrackingEmbedding(_FakeEmbeddingManager):
    """
    Records the maximum number of simultaneously active embed loops so tests
    can prove indexing jobs are serialized per service.
    """

    def __init__(self) -> None:
        self.active: int = 0
        self.max_active: int = 0
        self._guard = threading.Lock()

    def embed_documents(
        self,
        documents: list[str],
    ) -> list[list[float]]:
        with self._guard:
            self.active += 1
            self.max_active = max(self.max_active, self.active)

        time.sleep(0.05)

        try:
            return [[0.0] * 8 for _ in documents]
        finally:
            with self._guard:
                self.active -= 1


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
from sqlalchemy import select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core.config import RAGSettings  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.database.repositories import (  # noqa: E402
    EvidenceIndexStateRepository,
    PluginResultRepository,
)
from app.models.case import Case  # noqa: E402
from app.models.evidence_index_state import EvidenceIndexState  # noqa: E402
from app.models.memory_dump import MemoryDump  # noqa: E402
from app.models.plugin_execution import PluginExecution  # noqa: E402
from app.models.plugin_result import PluginResult  # noqa: E402
from app.services.rag.indexing_service import (  # noqa: E402
    RAGIndexingService,
)


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


def _new_service(embedding_manager=None, vector_store=None):
    return RAGIndexingService(
        embedding_manager=(
            embedding_manager if embedding_manager is not None
            else _FakeEmbeddingManager()
        ),
        vector_store=(
            vector_store if vector_store is not None
            else _RecordingVectorStore()
        ),
    )


def _add_evidence_rows(
    session: Session,
    investigation_id: str,
    count: int,
) -> None:
    """Append more evidence rows to an existing investigation."""

    dump = session.scalar(
        select(MemoryDump).where(
            MemoryDump.investigation_id == investigation_id
        )
    )
    execution = session.scalar(
        select(PluginExecution).where(
            PluginExecution.memory_dump_id == dump.id
        )
    )

    for index in range(count):
        session.add(
            PluginResult(
                plugin_execution_id=execution.id,
                artifact_type="pslist",
                artifact_name="windows.pslist",
                artifact_value=json.dumps(
                    {
                        "pid": 9000 + index,
                        "name": "lsass.exe",
                        "path": "C:\\Windows\\System32",
                    }
                ),
                confidence_score=100,
            )
        )

    session.commit()


# ==============================================================================
# Incremental semantics
# ==============================================================================


def test_index_is_incremental_no_work_on_rerun(session):
    """Re-running indexing on unchanged evidence must not re-embed anything."""

    investigation_id = _seed_evidence_rows(session, "INV-INCR", 25)

    store = _RecordingVectorStore()
    service = _new_service(vector_store=store)

    first = service.index_investigation(investigation_id, session)
    assert first["indexed"] == 25
    assert first["total"] == 25
    assert first["removed"] == 0

    store.added.clear()
    store.deleted.clear()

    second = service.index_investigation(investigation_id, session)
    assert second["indexed"] == 0
    assert second["total"] == 25
    assert second["removed"] == 0

    # Zero embedding / vector writes on the unchanged re-run.
    assert store.added == []
    assert store.deleted == []


def test_index_indexes_only_new_rows_on_rerun(session):
    """Rows added after the first index are the only ones embedded next run."""

    investigation_id = _seed_evidence_rows(session, "INV-NEW", 25)

    store = _RecordingVectorStore()
    service = _new_service(vector_store=store)

    first = service.index_investigation(investigation_id, session)
    assert first["indexed"] == 25

    _add_evidence_rows(session, investigation_id, 10)

    store.added.clear()

    second = service.index_investigation(investigation_id, session)
    assert second["indexed"] == 10
    assert second["total"] == 35
    assert second["removed"] == 0

    new_ids = second["indexed"]
    assert new_ids == 10

    # Exactly one batch of 10 new ids was written.
    assert len(store.added) == 1
    assert len(store.added[0]["ids"]) == 10


def test_index_reembeds_changed_evidence(session):
    """Evidence whose content changed must be re-embedded on the next run."""

    investigation_id = _seed_evidence_rows(session, "INV-CHG", 10)

    store = _RecordingVectorStore()
    service = _new_service(vector_store=store)

    first = service.index_investigation(investigation_id, session)
    assert first["indexed"] == 10

    record = PluginResultRepository(session).get_by_investigation(
        investigation_id
    )[0]

    record.artifact_value = json.dumps(
        {
            "pid": 1,
            "name": "malware.exe",
            "path": "C:\\Users\\Public\\pwned.exe",
        }
    )
    session.commit()

    store.added.clear()

    second = service.index_investigation(investigation_id, session)
    assert second["indexed"] == 1
    assert second["total"] == 10

    # The changed evidence id was rewritten (idempotent upsert keeps one vector).
    assert len(store.added) == 1
    assert store.added[0]["ids"] == [f"ev-{record.id}"]


def test_index_removes_stale_vectors_for_deleted_evidence(session):
    """Vectors whose evidence row no longer exists must be purged."""

    investigation_id = _seed_evidence_rows(session, "INV-STALE", 20)

    store = _RecordingVectorStore()
    service = _new_service(vector_store=store)

    first = service.index_investigation(investigation_id, session)
    assert first["indexed"] == 20

    records = PluginResultRepository(session).get_by_investigation(
        investigation_id
    )
    removed_record = records[0]
    session.delete(removed_record)
    session.commit()

    store.deleted.clear()

    second = service.index_investigation(investigation_id, session)
    assert second["indexed"] == 0
    assert second["total"] == 19
    assert second["removed"] == 1

    # The stale vector id was deleted from the store and state purged.
    assert f"ev-{removed_record.id}" in store.deleted

    state = EvidenceIndexStateRepository(session).get_by_investigation(
        investigation_id
    )
    assert removed_record.id not in state


def test_index_resumes_after_interrupted_state(session):
    """
    A row already written to the vector store but missing from the state table
    (simulated crash between upsert and checkpoint) is handled idempotently.
    """

    investigation_id = _seed_evidence_rows(session, "INV-RESUME", 5)

    store = _RecordingVectorStore()
    service = _new_service(vector_store=store)

    service.index_investigation(investigation_id, session)

    # Simulate a crash after the Chroma write but before the checkpoint by
    # clearing the state table while keeping the recorded vectors.
    state = EvidenceIndexStateRepository(session)
    state.delete_by_evidence_ids(
        [
            row.evidence_id
            for row in session.execute(
                select(EvidenceIndexState.evidence_id)
            ).all()
        ]
    )

    store.added.clear()

    # Re-running must not blow up and must re-record the checkpoint. The
    # idempotent upsert means no duplicate vectors are created.
    rerun = service.index_investigation(investigation_id, session)
    assert rerun["indexed"] == 5

    state = EvidenceIndexStateRepository(session).get_by_investigation(
        investigation_id
    )
    assert len(state) == 5


# ==============================================================================
# Bounded batches / configuration
# ==============================================================================


def test_index_streams_in_bounded_pages(session):
    """Evidence is read and written page by page, never wholesale."""

    investigation_id = _seed_evidence_rows(session, "INV-PAGES", 6000)

    store = _RecordingVectorStore()
    service = _new_service(vector_store=store)

    result = service.index_investigation(investigation_id, session)
    assert result["indexed"] == 6000

    # Six bounded pages: one vector batch per page, each at the page limit.
    assert len(store.added) == math.ceil(6000 / service.batch_size)
    for batch in store.added:
        assert len(batch["ids"]) <= service.batch_size
        assert len(batch["ids"]) <= 5461
        assert (
            len(batch["ids"])
            == len(batch["documents"])
            == len(batch["embeddings"])
            == len(batch["metadatas"])
        )


def test_index_batch_size_is_configurable(session, monkeypatch):
    """The page size must be configurable and honored."""

    monkeypatch.setattr(settings, "rag", RAGSettings(index_batch_size=40))

    investigation_id = _seed_evidence_rows(session, "INV-CONF", 100)

    store = _RecordingVectorStore()
    service = _new_service(vector_store=store)

    assert service.batch_size == 40

    result = service.index_investigation(investigation_id, session)
    assert result["indexed"] == 100

    assert len(store.added) == math.ceil(100 / 40)


def test_index_batch_size_is_capped_below_chroma_limit(session):
    """Batch sizes above the ChromaDB limit must be clamped."""

    investigation_id = _seed_evidence_rows(session, "INV-CAP", 5)

    store = _RecordingVectorStore()
    service = _new_service(vector_store=store)

    assert service.batch_size <= 5461
    assert service.index_investigation(investigation_id, session)["indexed"] == 5


def test_index_empty_investigation_returns_zeroes(session):
    """An investigation with no evidence indexes nothing."""

    investigation_id = _seed_evidence_rows(session, "INV-EMPTY", 0)

    store = _RecordingVectorStore()
    service = _new_service(vector_store=store)

    result = service.index_investigation(investigation_id, session)
    assert result == {"indexed": 0, "total": 0, "removed": 0}
    assert store.added == []


# ==============================================================================
# Serialization
# ==============================================================================


def test_indexing_runs_are_serialized_per_service(session_factory):
    """Concurrent indexing jobs on one service must not embed simultaneously."""

    inv_a = _seed_evidence_rows(session_factory(), "INV-CONC-A", 20)
    inv_b = _seed_evidence_rows(session_factory(), "INV-CONC-B", 20)

    embedding = _ConcurrencyTrackingEmbedding()
    store = _RecordingVectorStore()
    service = _new_service(
        embedding_manager=embedding,
        vector_store=store,
    )

    results: dict[str, dict] = {}

    def run(investigation_id: str) -> None:
        with session_factory() as db:
            results[investigation_id] = service.index_investigation(
                investigation_id,
                db,
            )

    first = threading.Thread(target=run, args=(inv_a,))
    second = threading.Thread(target=run, args=(inv_b,))

    first.start()
    second.start()
    first.join()
    second.join()

    # The lock serialized both jobs: never two active embed loops.
    assert embedding.max_active == 1
    assert results[inv_a]["indexed"] == 20
    assert results[inv_b]["indexed"] == 20
