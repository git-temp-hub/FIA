"""
Tests for investigation progress reporting.

Covers:
- ``compute_progress`` maps completed plugins to percentages (0/10=0% ...
  10/10=100%) and guards against invalid totals.
- ``POST /investigation/start`` persists progress after each completed
  plugin and records the current plugin while the loop is running.
- ``GET /investigation/status`` exposes live progress plus plugin counts
  and surfaces per-plugin failures instead of silently staying at 0%.

The heavy RAG modules are stubbed BEFORE ``indexing_service`` is ever
imported so the background post-processing tasks stay cheap and offline.
``app.services.investigation_service`` is replaced with a fake that drives
the route's plugin callbacks synchronously.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ==============================================================================
# Stubs for the heavy RAG modules (kept shape-compatible with the
# post-processing tests so the shared singletons behave in any order)
# ==============================================================================


class _FakeEmbeddingManager:
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
    def __init__(self) -> None:
        self.added: list[dict] = []

    def delete_by_metadata(self, where: dict) -> int:
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


sys.modules["app.services.rag.embedding_manager"] = (
    types.ModuleType("app.services.rag.embedding_manager")
)
sys.modules["app.services.rag.embedding_manager"].EmbeddingManager = (  # type: ignore[attr-defined]
    _FakeEmbeddingManager
)

sys.modules["app.services.rag.vector_store"] = types.ModuleType(
    "app.services.rag.vector_store"
)
sys.modules["app.services.rag.vector_store"].VectorStore = (  # type: ignore[attr-defined]
    _RecordingVectorStore
)


# ==============================================================================
# App imports (the investigation router is lightweight: its heavy
# ``investigation_service`` import is lazy inside the endpoint)
# ==============================================================================

from app.api.routes.investigation import (  # noqa: E402
    DEFAULT_PLUGINS,
    compute_progress,
)
from app.api.routes.investigation import (  # noqa: E402
    router as investigation_router,
)
from app.database.database import get_db  # noqa: E402
from app.database.repositories import (  # noqa: E402
    MemoryDumpRepository,
    PluginExecutionRepository,
)
from app.models.case import Case  # noqa: E402
from app.models.memory_dump import MemoryDump  # noqa: E402
from app.models.plugin_execution import PluginExecution  # noqa: E402


# ==============================================================================
# Fake investigation service
# ==============================================================================


class _FakeMeta:
    filename = "dump.raw"
    original_path = Path("/tmp/dump.raw")
    stored_path = Path("/storage/dump.raw")
    sha256 = "0" * 64
    file_size = 1024


class _FakeResult:
    def __init__(
        self,
        plugin: str,
        success: bool = True,
        stderr: str = "",
    ) -> None:
        self.plugin = plugin
        self.success = success
        self.stderr = stderr
        self.json_output = None


class _FakeInvestigationService:
    """
    Drives the route's plugin callbacks like the real service would,
    recording the persisted progress/current-plugin after each plugin.
    """

    def __init__(
        self,
        session_factory,
        investigation_id: str = "",
    ) -> None:
        self._session_factory = session_factory
        self.investigation_id = investigation_id
        self.plugins: list[str] = []
        self.initial_snapshot: dict | None = None
        self.snapshots: list[dict] = []

    def prepare_memory_dump(self, memory_dump: Path) -> _FakeMeta:
        return _FakeMeta()

    def _read_snapshot(self) -> dict:
        with self._session_factory() as db:
            record = MemoryDumpRepository(db).get_by_investigation_id(
                self.investigation_id
            )
            executions = PluginExecutionRepository(db).get_by_memory_dump(
                record.id
            )

        return {
            "progress": record.progress,
            "current_plugin": record.current_plugin,
            "completed": sum(
                1
                for execution in executions
                if execution.execution_status == "completed"
            ),
            "failed": sum(
                1
                for execution in executions
                if execution.execution_status == "failed"
            ),
            "total": len(executions),
        }

    def run_investigation(
        self,
        memory_dump: Path,
        plugins: list[str],
        on_plugin_started=None,
        on_plugin_completed=None,
    ):
        self.plugins = list(plugins)
        self.initial_snapshot = self._read_snapshot()

        results = []
        total = len(plugins)

        for index, plugin_name in enumerate(plugins):

            if on_plugin_started is not None:
                on_plugin_started(plugin_name)

            result = _FakeResult(plugin_name)

            if on_plugin_completed is not None:
                on_plugin_completed(index, total, result, 0.01)

            results.append(result)
            self.snapshots.append(self._read_snapshot())

        return results


_INVESTIGATION_SERVICE_STUB = types.ModuleType(
    "app.services.investigation_service"
)
sys.modules["app.services.investigation_service"] = (
    _INVESTIGATION_SERVICE_STUB
)


@pytest.fixture()
def fake_investigation_service(session_factory):
    fake = _FakeInvestigationService(
        session_factory,
        investigation_id="INV-PROGRESS",
    )
    _INVESTIGATION_SERVICE_STUB.investigation_service = fake

    yield fake

    _INVESTIGATION_SERVICE_STUB.investigation_service = None


@pytest.fixture()
def investigation_client(session_factory):
    test_app = FastAPI()
    test_app.include_router(investigation_router)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    test_app.dependency_overrides[get_db] = override_get_db

    return TestClient(test_app)


def _seed_status_investigation(
    session_factory,
    investigation_id: str,
    status: str,
    progress: int,
    current_plugin: str | None,
    executions: list[tuple[str, str]],
) -> None:
    """Seed a MemoryDump plus plugin executions for status tests."""

    with session_factory() as db:
        case = Case(
            case_name=investigation_id,
            investigator="tester",
            description="t",
        )
        db.add(case)
        db.flush()

        dump = MemoryDump(
            case_id=case.id,
            investigation_id=investigation_id,
            filename="dump.raw",
            original_path="/tmp/dump.raw",
            stored_path="/storage/dump.raw",
            sha256_hash="0" * 64,
            file_size=1024,
            status=status,
            progress=progress,
            current_plugin=current_plugin,
        )
        db.add(dump)
        db.flush()

        for plugin_name, execution_status in executions:
            db.add(
                PluginExecution(
                    memory_dump_id=dump.id,
                    plugin_name=plugin_name,
                    execution_status=execution_status,
                    error_message=(
                        "plugin exploded"
                        if execution_status == "failed"
                        else None
                    ),
                )
            )

        db.commit()


# ==============================================================================
# Progress calculation
# ==============================================================================


def test_compute_progress_maps_completed_plugins_to_percentage():
    percentages = [
        compute_progress(completed, 10)
        for completed in range(11)
    ]

    assert percentages == [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]


def test_compute_progress_guards_invalid_inputs():
    assert compute_progress(0, 0) == 0
    assert compute_progress(0, 10) == 0
    assert compute_progress(10, 10) == 100
    # Never exceeds 100 even if more plugins report than scheduled.
    assert compute_progress(12, 10) == 100


# ==============================================================================
# Progress persistence during a run
# ==============================================================================


def test_start_investigation_starts_at_zero_and_updates_per_plugin(
    investigation_client,
    fake_investigation_service,
):
    investigation_id = "INV-PROGRESS"

    response = investigation_client.post(
        "/investigation/start",
        json={
            "investigation_id": investigation_id,
            "memory_dump_path": "/tmp/dump.raw",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "completed"

    # Ten default plugins ran against the scheduled list.
    assert fake_investigation_service.plugins == DEFAULT_PLUGINS
    assert len(fake_investigation_service.plugins) == 10

    # Progress starts at 0 before any plugin finishes.
    assert fake_investigation_service.initial_snapshot == {
        "progress": 0,
        "current_plugin": None,
        "completed": 0,
        "failed": 0,
        "total": 0,
    }

    # Every completed plugin advances progress by one 10% step.
    expected_progress = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

    for snapshot, expected in zip(
        fake_investigation_service.snapshots,
        expected_progress,
    ):
        assert snapshot["progress"] == expected
        assert snapshot["completed"] == snapshot["total"]
        assert snapshot["failed"] == 0

    # The plugin currently executing is persisted for the status endpoint.
    assert fake_investigation_service.snapshots[0]["current_plugin"] == (
        DEFAULT_PLUGINS[0]
    )
    assert fake_investigation_service.snapshots[-1]["current_plugin"] == (
        DEFAULT_PLUGINS[-1]
    )


def test_start_investigation_persists_final_completed_state(
    investigation_client,
    fake_investigation_service,
    session_factory,
):
    investigation_id = "INV-PROGRESS-FIN"
    fake_investigation_service.investigation_id = investigation_id

    response = investigation_client.post(
        "/investigation/start",
        json={
            "investigation_id": investigation_id,
            "memory_dump_path": "/tmp/dump.raw",
        },
    )

    assert response.status_code == 200

    with session_factory() as db:
        record = MemoryDumpRepository(db).get_by_investigation_id(
            investigation_id
        )

        assert record.status == "completed"
        assert record.progress == 100
        # Not marked completed while plugins were still finishing is handled
        # by the route: final status is only set after the loop returns.
        assert record.current_plugin == DEFAULT_PLUGINS[-1]

        executions = PluginExecutionRepository(db).get_by_memory_dump(
            record.id
        )
        assert len(executions) == 10
        assert all(
            execution.execution_status == "completed"
            for execution in executions
        )


# ==============================================================================
# Status endpoint live reporting
# ==============================================================================


def test_status_reports_zero_progress_for_new_investigation(
    investigation_client,
    session_factory,
):
    investigation_id = "INV-STATUS-NEW"

    _seed_status_investigation(
        session_factory,
        investigation_id,
        status="running",
        progress=0,
        current_plugin=None,
        executions=[],
    )

    response = investigation_client.get(
        f"/investigation/status/{investigation_id}"
    )

    assert response.status_code == 200
    payload = response.json()

    assert payload["status"] == "running"
    assert payload["progress"] == 0
    assert payload["current_plugin"] is None
    assert payload["total_plugins"] == 0
    assert payload["completed_plugins"] == 0
    assert payload["failed_plugins"] == 0
    assert payload["last_error"] is None


def test_status_reports_running_progress_and_plugin_counts(
    investigation_client,
    session_factory,
):
    investigation_id = "INV-STATUS-RUN"

    _seed_status_investigation(
        session_factory,
        investigation_id,
        status="running",
        progress=30,
        current_plugin="windows.pslist",
        executions=[
            ("windows.info", "completed"),
            ("windows.pslist", "completed"),
            ("windows.pstree", "completed"),
            ("windows.cmdline", "running"),
        ],
    )

    response = investigation_client.get(
        f"/investigation/status/{investigation_id}"
    )

    assert response.status_code == 200
    payload = response.json()

    assert payload["status"] == "running"
    assert payload["progress"] == 30
    assert payload["current_plugin"] == "windows.pslist"
    assert payload["total_plugins"] == 4
    assert payload["completed_plugins"] == 3
    assert payload["failed_plugins"] == 0
    assert payload["last_error"] is None


def test_status_reports_failed_plugins_and_last_error(
    investigation_client,
    session_factory,
):
    investigation_id = "INV-STATUS-FAIL"

    _seed_status_investigation(
        session_factory,
        investigation_id,
        status="running",
        progress=50,
        current_plugin="windows.malfind",
        executions=[
            ("windows.info", "completed"),
            ("windows.pslist", "completed"),
            ("windows.dlllist", "completed"),
            ("windows.malfind", "failed"),
        ],
    )

    response = investigation_client.get(
        f"/investigation/status/{investigation_id}"
    )

    assert response.status_code == 200
    payload = response.json()

    assert payload["status"] == "running"
    assert payload["progress"] == 50
    assert payload["total_plugins"] == 4
    assert payload["completed_plugins"] == 3
    assert payload["failed_plugins"] == 1
    assert payload["last_error"] == "plugin exploded"


def test_status_reports_completed_investigation(
    investigation_client,
    session_factory,
):
    investigation_id = "INV-STATUS-DONE"

    _seed_status_investigation(
        session_factory,
        investigation_id,
        status="completed",
        progress=100,
        current_plugin="windows.malfind",
        executions=[
            ("windows.info", "completed"),
            ("windows.pslist", "completed"),
        ],
    )

    response = investigation_client.get(
        f"/investigation/status/{investigation_id}"
    )

    assert response.status_code == 200
    payload = response.json()

    assert payload["status"] == "completed"
    assert payload["progress"] == 100
    assert payload["completed_plugins"] == 2
    assert payload["total_plugins"] == 2