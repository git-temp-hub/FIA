"""
Pytest configuration for the FIA backend regression suite.

Isolation guarantees
--------------------
* ``DATABASE_PATH`` is redirected to a temporary SQLite file BEFORE any
  application module is imported, so the real ``storage/database/fia.db``
  is never read or modified by tests.
* The heavy ``app.services.ai_investigation_service`` module (which loads
  SentenceTransformer, ChromaDB, and Ollama at import time) is replaced by
  a lightweight stub so the chat API tests run fast and offline.
"""

import os
import sys
import tempfile
import types

# Must be set before any application import so the application engine
# is never bound to the real database file.
_TEMP_DIR = tempfile.mkdtemp(prefix="fia-tests-")

os.environ["DATABASE_PATH"] = os.path.join(
    _TEMP_DIR,
    "fia_test.db",
)


class _FakeAIInvestigationService:
    """
    Minimal stand-in for ``ai_investigation_service``.

    Only ``answer()`` is needed by the chat route; it returns a canned,
    citation-free result so no LLM/retrieval stack is required.
    """

    def answer(
        self,
        investigation_id: str,
        question: str,
        top_k: int = 6,
        db=None,
    ) -> dict:
        return {
            "question": question,
            "answer": f"Mock answer for: {question}",
            "confidence": 85,
            "insufficient": False,
            "citations": [],
            "references": [],
        }


_fake_module = types.ModuleType(
    "app.services.ai_investigation_service"
)
_fake_module.ai_investigation_service = _FakeAIInvestigationService()
sys.modules["app.services.ai_investigation_service"] = _fake_module

# ==============================================================================
# Imports (must come after the environment/stub setup above)
# ==============================================================================

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

import app.models  # noqa: E402, F401  (registers all ORM tables)
from app.api.routes.chat import router as chat_router  # noqa: E402
from app.api.routes.reports import router as reports_router  # noqa: E402
from app.database.database import Base  # noqa: E402
from app.database.database import get_db  # noqa: E402
from app.models.case import Case  # noqa: E402
from app.models.memory_dump import MemoryDump  # noqa: E402


# ==============================================================================
# Fixtures
# ==============================================================================


@pytest.fixture()
def engine(tmp_path):
    """Fresh file-backed SQLite engine with the full application schema."""

    db_path = tmp_path / "fia_test.db"

    test_engine = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )

    Base.metadata.create_all(test_engine)

    yield test_engine

    test_engine.dispose()


@pytest.fixture()
def session_factory(engine):
    """Session factory bound to the isolated test engine."""

    return sessionmaker(
        bind=engine,
        class_=Session,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )


@pytest.fixture()
def session(session_factory):
    """Single database session for direct repository/ORM assertions."""

    db = session_factory()

    yield db

    db.close()


@pytest.fixture()
def client(session_factory):
    """
    FastAPI TestClient exposing only the chat and reports routers,
    with the database dependency overridden to the isolated engine.
    """

    test_app = FastAPI()

    test_app.include_router(chat_router)
    test_app.include_router(reports_router)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    test_app.dependency_overrides[get_db] = override_get_db

    return TestClient(test_app)


@pytest.fixture()
def seed_investigation(session):
    """Create a Case + MemoryDump for an investigation id."""

    def _seed(
        investigation_id: str,
        filename: str = "dump.raw",
    ):
        case = Case(
            case_name=investigation_id,
            investigator="tester",
            description=f"Test investigation {investigation_id}",
        )

        session.add(case)
        session.flush()

        dump = MemoryDump(
            case_id=case.id,
            investigation_id=investigation_id,
            filename=filename,
            original_path=f"/tmp/{filename}",
            stored_path=f"/storage/{filename}",
            sha256_hash="0" * 64,
            file_size=1024,
            status="completed",
            progress=100,
        )

        session.add(dump)
        session.flush()
        session.commit()

        return case, dump

    return _seed
