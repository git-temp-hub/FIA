"""
Tests for streaming upload (Phase 2).

Guarantees that multi-gigabyte memory dumps are written to disk in bounded
chunks (never buffered fully in memory), validated and hashed incrementally,
and that the upload endpoint still produces the exact same response contract
and database records as before.

``app.services.investigation_service`` is replaced in ``sys.modules`` before
the upload router is imported (the same pattern used by
``test_investigation_progress``) because the real service eagerly imports the
Volatility stack. The stub's ``prepare_memory_dump_stream`` delegates to the
REAL :class:`MemoryDumpManager`, so the endpoint test still exercises actual
chunked storage and hashing.
"""

from __future__ import annotations

import hashlib
import sys
import types

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.volatility import memory_dump_manager as manager_module
from app.volatility.memory_dump_manager import memory_dump_manager


class _ChunkReader:
    """Async reader that yields ``chunk_size`` bytes at a time."""

    def __init__(self, data: bytes, chunk_size: int = 1024):
        self._data = data
        self._chunk_size = chunk_size
        self._offset = 0

    async def read(self, size: int = -1) -> bytes:
        if self._offset >= len(self._data):
            return b""
        step = self._chunk_size if size < 0 else min(size, self._chunk_size)
        chunk = self._data[self._offset: self._offset + step]
        self._offset += len(chunk)
        return chunk


class _FakeInvestigationService:
    """Delegates streaming to the real memory dump manager."""

    async def prepare_memory_dump_stream(self, filename, stream):
        return await memory_dump_manager.stream_to_storage(
            filename=filename,
            stream=stream,
        )


# The upload router imports ``investigation_service`` eagerly at module load,
# while the investigation router resolves it lazily per call. ``test_investigation
# _progress`` installs a shared stub module in ``sys.modules`` for that lazy
# path; we must reuse the SAME module object (never replace it) and only set a
# temporary attribute during the eager import, so the other file's per-test
# fixture keeps working when the full suite runs together.
_investigation_module = sys.modules.get("app.services.investigation_service")

if _investigation_module is None:
    _investigation_module = types.ModuleType("app.services.investigation_service")
    sys.modules["app.services.investigation_service"] = _investigation_module

_previous_investigation_service = getattr(
    _investigation_module,
    "investigation_service",
    None,
)

_investigation_module.investigation_service = _FakeInvestigationService()

try:
    from app.api.routes.upload import router as upload_router  # noqa: E402
finally:
    _investigation_module.investigation_service = (
        _previous_investigation_service
    )

from app.database.database import Base, get_db  # noqa: E402
from app.models.memory_dump import MemoryDump  # noqa: E402


def _redirect_storage(monkeypatch, tmp_path):
    """Redirect the manager's storage to its own subdirectory of tmp_path.

    A dedicated subdirectory is used because the SQLite test database also
    lives directly inside ``tmp_path`` and would otherwise pollute the
    "nothing stored" assertions.
    """

    storage = tmp_path / "uploads"
    storage.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(memory_dump_manager, "_storage_directory", storage)
    return storage


# ==============================================================================
# MemoryDumpManager.stream_to_storage
# ==============================================================================


@pytest.mark.asyncio
async def test_stream_to_storage_stores_hashes_and_sizes(tmp_path, monkeypatch):
    storage = _redirect_storage(monkeypatch, tmp_path)

    payload = b"hello-memory-dump" * 1000

    info = await memory_dump_manager.stream_to_storage(
        filename="evidence.raw",
        stream=_ChunkReader(payload, chunk_size=4096),
    )

    assert info.filename == "evidence.raw"
    assert info.extension == ".raw"
    assert info.file_size == len(payload)
    assert info.sha256 == hashlib.sha256(payload).hexdigest()

    stored = storage / "evidence.raw"
    assert stored.exists()
    assert stored.read_bytes() == payload

    assert info.stored_path == stored
    assert list(storage.iterdir()) == [stored]


@pytest.mark.asyncio
async def test_stream_to_storage_rejects_unsupported_extension(
    tmp_path,
    monkeypatch,
):
    storage = _redirect_storage(monkeypatch, tmp_path)

    with pytest.raises(ValueError, match="Unsupported memory dump format"):
        await memory_dump_manager.stream_to_storage(
            filename="evidence.zip",
            stream=_ChunkReader(b"data"),
        )

    assert list(storage.iterdir()) == []


@pytest.mark.asyncio
async def test_stream_to_storage_rejects_empty_upload(tmp_path, monkeypatch):
    storage = _redirect_storage(monkeypatch, tmp_path)

    with pytest.raises(ValueError, match="empty"):
        await memory_dump_manager.stream_to_storage(
            filename="empty.raw",
            stream=_ChunkReader(b""),
        )

    assert list(storage.iterdir()) == []


@pytest.mark.asyncio
async def test_stream_to_storage_rejects_oversized_upload(tmp_path, monkeypatch):
    storage = _redirect_storage(monkeypatch, tmp_path)

    monkeypatch.setattr(manager_module, "MAX_MEMORY_DUMP_SIZE", 2048)

    with pytest.raises(ValueError, match="exceeds the maximum"):
        await memory_dump_manager.stream_to_storage(
            filename="huge.raw",
            stream=_ChunkReader(b"x" * 4096, chunk_size=1024),
        )

    assert list(storage.iterdir()) == []


@pytest.mark.asyncio
async def test_stream_to_storage_does_not_overwrite_existing(
    tmp_path,
    monkeypatch,
):
    storage = _redirect_storage(monkeypatch, tmp_path)

    existing = storage / "same.raw"
    existing.write_bytes(b"pre-existing")

    info = await memory_dump_manager.stream_to_storage(
        filename="same.raw",
        stream=_ChunkReader(b"new-content"),
    )

    assert existing.read_bytes() == b"pre-existing"
    assert info.stored_path == existing
    assert info.file_size == len(b"new-content")
    assert info.sha256 == hashlib.sha256(b"new-content").hexdigest()

    assert list(storage.iterdir()) == [existing]


@pytest.mark.asyncio
async def test_stream_to_storage_sanitizes_filename(tmp_path, monkeypatch):
    storage = _redirect_storage(monkeypatch, tmp_path)

    info = await memory_dump_manager.stream_to_storage(
        filename="../../evil/../dump.raw",
        stream=_ChunkReader(b"data"),
    )

    assert info.filename == "dump.raw"
    assert info.stored_path == storage / "dump.raw"
    assert (storage / "dump.raw").exists()


@pytest.mark.asyncio
async def test_stream_to_storage_chunked_hashing_matches_single_read(
    tmp_path,
    monkeypatch,
):
    storage = _redirect_storage(monkeypatch, tmp_path)

    payload = bytes(range(256)) * 5000  # ~1.2 MB across many chunks

    info = await memory_dump_manager.stream_to_storage(
        filename="big.mem",
        stream=_ChunkReader(payload, chunk_size=65536),
    )

    assert info.sha256 == hashlib.sha256(payload).hexdigest()
    assert info.file_size == len(payload)


# ==============================================================================
# Upload endpoint (response contract + persistence)
# ==============================================================================


def _upload_client(session_factory):
    app = FastAPI()
    app.include_router(upload_router)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    return TestClient(app)


def test_upload_endpoint_streams_and_persists(
    tmp_path,
    monkeypatch,
    engine,
    session_factory,
):
    storage = _redirect_storage(monkeypatch, tmp_path)

    Base.metadata.create_all(engine)

    client = _upload_client(session_factory)

    payload = b"fake-memory-dump-bytes" * 5000

    response = client.post(
        "/upload/",
        files={"file": ("dump.mem", payload, "application/octet-stream")},
    )

    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "success"
    assert body["filename"] == "dump.mem"
    assert body["size"] == len(payload)
    assert body["sha256"] == hashlib.sha256(payload).hexdigest()
    assert body["investigation_id"]

    stored = storage / "dump.mem"
    assert stored.exists()
    assert stored.read_bytes() == payload

    with session_factory() as db:
        record = db.query(MemoryDump).filter_by(
            investigation_id=body["investigation_id"],
        ).first()

        assert record is not None
        assert record.filename == "dump.mem"
        assert record.sha256_hash == body["sha256"]
        assert record.file_size == len(payload)
        assert record.status == "uploaded"
        assert record.progress == 0
        assert str(record.stored_path).endswith("dump.mem")


def test_upload_endpoint_rejects_bad_extension(
    tmp_path,
    monkeypatch,
    engine,
    session_factory,
):
    storage = _redirect_storage(monkeypatch, tmp_path)

    Base.metadata.create_all(engine)

    client = _upload_client(session_factory)

    response = client.post(
        "/upload/",
        files={"file": ("report.pdf", b"x", "application/octet-stream")},
    )

    assert response.status_code == 400
    assert "Unsupported memory dump format" in response.json()["detail"]
    assert list(storage.iterdir()) == []

    with session_factory() as db:
        assert db.query(MemoryDump).count() == 0


def test_upload_endpoint_rejects_empty_file(
    tmp_path,
    monkeypatch,
    engine,
    session_factory,
):
    storage = _redirect_storage(monkeypatch, tmp_path)

    Base.metadata.create_all(engine)

    client = _upload_client(session_factory)

    response = client.post(
        "/upload/",
        files={"file": ("empty.raw", b"", "application/octet-stream")},
    )

    assert response.status_code == 400
    assert "empty" in response.json()["detail"]
    assert list(storage.iterdir()) == []

    with session_factory() as db:
        assert db.query(MemoryDump).count() == 0