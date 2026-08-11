"""
API-level regression tests for conversation session isolation.

Requirements covered:
    A  Session 1 messages appear in Session 1.
    B  Session 2 messages appear in Session 2.
    C  Session 1 messages do NOT appear in Session 2.
    D  Messages from investigation A never appear in investigation B.
    J  Legacy NULL-session messages are preserved.
"""

from app.database.repositories import ChatMessageRepository
from app.models.chat_message import ChatMessage


def _ask(client, investigation_id, session_id, question):
    payload = {
        "investigation_id": investigation_id,
        "question": question,
    }

    if session_id is not None:
        payload["session_id"] = session_id

    return client.post("/chat/query", json=payload)


def _history(client, investigation_id, session_id=None):
    params = {"session_id": session_id} if session_id else None

    return client.get(
        f"/chat/history/{investigation_id}",
        params=params,
    )


def _contents(response) -> list[str]:
    return [
        message["content"]
        for message in response.json()["messages"]
    ]


# ----------------------------------------------------------------------
# Session storage and retrieval
# ----------------------------------------------------------------------


def test_query_stores_session_and_history_returns_it(
    client,
    seed_investigation,
):
    seed_investigation("INV-A")

    response = _ask(client, "INV-A", "s1", "Which processes ran?")

    assert response.status_code == 200
    assert response.json()["session_id"] == "s1"

    history = _history(client, "INV-A", "s1")

    assert history.status_code == 200
    assert history.json()["session_id"] == "s1"
    assert _contents(history) == [
        "Which processes ran?",
        "Mock answer for: Which processes ran?",
    ]


# ----------------------------------------------------------------------
# Session isolation
# ----------------------------------------------------------------------


def test_session1_messages_do_not_appear_in_session2(
    client,
    seed_investigation,
):
    seed_investigation("INV-A")

    _ask(client, "INV-A", "s1", "S1 question")
    _ask(client, "INV-A", "s2", "S2 question")

    session1 = _contents(_history(client, "INV-A", "s1"))
    session2 = _contents(_history(client, "INV-A", "s2"))

    assert "S1 question" in session1
    assert "S2 question" not in session1

    assert "S2 question" in session2
    assert "S1 question" not in session2


def test_each_session_keeps_its_own_full_history(
    client,
    seed_investigation,
):
    seed_investigation("INV-A")

    _ask(client, "INV-A", "s1", "S1 first")
    _ask(client, "INV-A", "s2", "S2 first")
    _ask(client, "INV-A", "s1", "S1 second")

    session1 = _contents(_history(client, "INV-A", "s1"))
    session2 = _contents(_history(client, "INV-A", "s2"))

    assert session1 == [
        "S1 first",
        "Mock answer for: S1 first",
        "S1 second",
        "Mock answer for: S1 second",
    ]
    assert session2 == [
        "S2 first",
        "Mock answer for: S2 first",
    ]


# ----------------------------------------------------------------------
# Investigation isolation
# ----------------------------------------------------------------------


def test_investigations_are_isolated_via_api(
    client,
    seed_investigation,
):
    seed_investigation("INV-A")
    seed_investigation("INV-B")

    _ask(client, "INV-A", "s1", "A question")
    _ask(client, "INV-B", "s1", "B question")

    a_contents = _contents(_history(client, "INV-A", "s1"))
    b_contents = _contents(_history(client, "INV-B", "s1"))

    assert "A question" in a_contents
    assert "B question" not in a_contents

    assert "B question" in b_contents
    assert "A question" not in b_contents


# ----------------------------------------------------------------------
# Legacy behavior and data preservation
# ----------------------------------------------------------------------


def test_new_session_starts_empty_and_excludes_legacy(
    client,
    session,
    seed_investigation,
):
    seed_investigation("INV-A")

    # Emulate pre-session data: messages stored with NULL session_id.
    repository = ChatMessageRepository(session)

    repository.create(
        ChatMessage(
            investigation_id="INV-A",
            session_id=None,
            role="user",
            content="legacy question",
        )
    )
    repository.create(
        ChatMessage(
            investigation_id="INV-A",
            session_id=None,
            role="assistant",
            content="legacy answer",
        )
    )

    # Legacy rows must still exist.
    assert len(repository.get_by_investigation("INV-A")) == 2

    # A brand-new session must NOT fall back to NULL-session messages.
    history = _history(client, "INV-A", "fresh-session")

    assert history.status_code == 200
    assert history.json()["session_id"] == "fresh-session"
    assert history.json()["messages"] == []

    # Legacy rows must still exist after the API calls.
    assert len(repository.get_by_investigation("INV-A")) == 2


def test_backward_compatibility_without_session_id(
    client,
    seed_investigation,
):
    seed_investigation("INV-A")

    # Legacy client: query without a session_id.
    response = _ask(client, "INV-A", None, "Legacy question")

    assert response.status_code == 200
    assert response.json()["session_id"] is None

    # Legacy client: history without a session_id returns everything.
    history = _history(client, "INV-A")

    assert history.status_code == 200
    assert history.json()["session_id"] is None
    assert len(history.json()["messages"]) == 2
