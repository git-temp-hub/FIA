"""
Repository and migration regression tests for conversation session
isolation inside an investigation.

Requirements covered:
    A/B/C  Session messages appear only in their own session.
    D      Messages from investigation A never appear in investigation B.
    J      Legacy NULL-session messages are preserved.
    Schema The session_id column migration is backward compatible.
"""

from sqlalchemy import create_engine
from sqlalchemy import text

from app.database.database import ensure_chat_session_column
from app.database.repositories import ChatMessageRepository
from app.models.chat_message import ChatMessage


def _add_message(
    repo: ChatMessageRepository,
    investigation_id: str,
    session_id: str | None,
    role: str,
    content: str,
) -> ChatMessage:
    return repo.create(
        ChatMessage(
            investigation_id=investigation_id,
            session_id=session_id,
            role=role,
            content=content,
        )
    )


def _contents(messages) -> list[str]:
    return [message.content for message in messages]


# ----------------------------------------------------------------------
# Repository session isolation
# ----------------------------------------------------------------------


def test_get_by_investigation_filters_by_session(session):
    repo = ChatMessageRepository(session)

    _add_message(repo, "INV-A", "s1", "user", "S1 question")
    _add_message(repo, "INV-A", "s1", "assistant", "S1 answer")
    _add_message(repo, "INV-A", "s2", "user", "S2 question")
    _add_message(repo, "INV-A", "s2", "assistant", "S2 answer")

    session1 = repo.get_by_investigation("INV-A", session_id="s1")
    session2 = repo.get_by_investigation("INV-A", session_id="s2")

    assert _contents(session1) == ["S1 question", "S1 answer"]
    assert _contents(session2) == ["S2 question", "S2 answer"]


def test_sessions_do_not_leak_into_each_other(session):
    repo = ChatMessageRepository(session)

    _add_message(repo, "INV-A", "s1", "user", "A S1 question")
    _add_message(repo, "INV-A", "s2", "user", "A S2 question")

    session1 = repo.get_by_investigation("INV-A", session_id="s1")
    session2 = repo.get_by_investigation("INV-A", session_id="s2")

    assert _contents(session1) == ["A S1 question"]
    assert _contents(session2) == ["A S2 question"]


def test_investigations_are_isolated(session):
    repo = ChatMessageRepository(session)

    _add_message(repo, "INV-A", "s1", "user", "A question")
    _add_message(repo, "INV-B", "s1", "user", "B question")

    a_history = repo.get_by_investigation("INV-A", session_id="s1")
    b_history = repo.get_by_investigation("INV-B", session_id="s1")

    assert _contents(a_history) == ["A question"]
    assert _contents(b_history) == ["B question"]


def test_session_scope_excludes_legacy_null_messages(session):
    repo = ChatMessageRepository(session)

    _add_message(repo, "INV-A", None, "user", "legacy question")
    _add_message(repo, "INV-A", None, "assistant", "legacy answer")
    _add_message(repo, "INV-A", "s1", "user", "new session question")

    scoped = repo.get_by_investigation("INV-A", session_id="s1")
    unscoped = repo.get_by_investigation("INV-A")

    assert _contents(scoped) == ["new session question"]
    assert len(unscoped) == 3


def test_legacy_null_messages_are_not_deleted(session):
    repo = ChatMessageRepository(session)

    _add_message(repo, "INV-A", None, "user", "legacy")

    # Read history through both scoped and unscoped paths.
    repo.get_by_investigation("INV-A", session_id="s1")
    repo.get_by_investigation("INV-A")

    remaining = repo.get_by_investigation("INV-A")

    assert _contents(remaining) == ["legacy"]


# ----------------------------------------------------------------------
# Schema migration
# ----------------------------------------------------------------------


def test_ensure_chat_session_column_is_backward_compatible(tmp_path):
    db_path = tmp_path / "legacy.db"

    legacy_engine = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )

    # Emulate the pre-session schema: chat_messages without session_id.
    with legacy_engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE chat_messages ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "investigation_id VARCHAR(64) NOT NULL, "
                "role VARCHAR(20) NOT NULL, "
                "content TEXT NOT NULL, "
                "citations TEXT, "
                "confidence INTEGER, "
                "created_at DATETIME NOT NULL"
                ")"
            )
        )
        connection.execute(
            text(
                "INSERT INTO chat_messages "
                "(investigation_id, role, content, created_at) "
                "VALUES (:inv, :role, :content, :created)"
            ),
            {
                "inv": "INV-LEGACY",
                "role": "user",
                "content": "old message",
                "created": "2026-08-05 00:00:00",
            },
        )

    ensure_chat_session_column(legacy_engine)

    with legacy_engine.connect() as connection:
        columns = {
            row[1]
            for row in connection.execute(
                text("PRAGMA table_info(chat_messages)")
            )
        }

        assert "session_id" in columns

        row = connection.execute(
            text(
                "SELECT investigation_id, session_id "
                "FROM chat_messages WHERE id = 1"
            )
        ).fetchone()

        # Existing rows are untouched; the new column is NULL.
        assert row[0] == "INV-LEGACY"
        assert row[1] is None

    legacy_engine.dispose()


def test_ensure_chat_session_column_is_idempotent(tmp_path):
    db_path = tmp_path / "idempotent.db"

    test_engine = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )

    from app.database.database import Base

    import app.models  # noqa: F401

    Base.metadata.create_all(test_engine)

    ensure_chat_session_column(test_engine)
    ensure_chat_session_column(test_engine)

    with test_engine.connect() as connection:
        columns = {
            row[1]
            for row in connection.execute(
                text("PRAGMA table_info(chat_messages)")
            )
        }

        assert "session_id" in columns
        assert len(
            [
                column
                for column in columns
                if column == "session_id"
            ]
        ) == 1

    test_engine.dispose()
