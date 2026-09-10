"""
Streaming must be a delivery change only.

Every safety mechanism built across Phases 2, 5 and 8 — citation parsing,
confidence calibration, signature corroboration, the malfind ceiling — runs on
the finished text. Streaming exists so the answer appears progressively; it
must not change a single value those mechanisms produce.

These tests pin that: the same prompt streamed and unstreamed must yield the
same complete text, and the four sections plus the CONFIDENCE line the parser
depends on must survive the prompt rewrite.
"""

from __future__ import annotations

import pytest

from app.llm.confidence import extract_assessment
from app.llm.llm_manager import LLMManager, LLMSettings
from app.llm.prompt_builder import PromptBuilder
from app.llm.response_parser import ResponseParser

CHUNKS = [
    "FINDING\n",
    "`svchost.exe` (PID 1600) was listening on port 49694 [1].\n\n",
    "EVIDENCE\n",
    "The connection is bound locally [1][2].\n\n",
    "ASSESSMENT\n",
    "Support is moderate.\n\n",
    "GAPS\nNone.\n\n",
    "CONFIDENCE: 60",
]

WHOLE = "".join(CHUNKS)


class _FakeClient:
    """Minimal stand-in for the Ollama client."""

    def __init__(self) -> None:
        self.stream_requested: bool | None = None

    def list(self):  # pragma: no cover - only used by verify_model
        raise NotImplementedError

    def chat(self, model, messages, stream, options):
        self.stream_requested = stream

        if stream:
            return iter(
                {"message": {"content": piece}} for piece in CHUNKS
            )

        return {"message": {"content": WHOLE}}


def _manager(client: _FakeClient) -> LLMManager:
    manager = LLMManager(
        settings=LLMSettings(
            ollama_host="http://localhost:11434",
            llm_model="test-model",
        )
    )
    manager._client = client
    manager.verify_model = lambda: None  # type: ignore[method-assign]
    return manager


# ------------------------------------------------------------------
# Delivery vs content
# ------------------------------------------------------------------

def test_streaming_returns_the_same_complete_text_as_not_streaming():
    """The whole point: downstream cannot tell the difference."""

    plain = _manager(_FakeClient()).generate("prompt")

    seen: list[str] = []
    streamed = _manager(_FakeClient()).generate(
        "prompt", on_token=seen.append
    )

    assert streamed == plain == WHOLE
    assert "".join(seen) == WHOLE


def test_stream_is_requested_only_when_a_consumer_is_given():
    client = _FakeClient()
    _manager(client).generate("prompt")
    assert client.stream_requested is False

    client = _FakeClient()
    _manager(client).generate("prompt", on_token=lambda _: None)
    assert client.stream_requested is True


def test_chunks_arrive_progressively_not_all_at_once():
    seen: list[str] = []
    _manager(_FakeClient()).generate("prompt", on_token=seen.append)
    assert len(seen) == len(CHUNKS)


def test_a_failing_consumer_does_not_lose_the_generation():
    """
    A broken client connection must not discard an answer that has already
    been paid for: the text still returns, and is still parsed and enforced
    against.
    """

    def explode(_chunk: str) -> None:
        raise RuntimeError("client went away")

    assert _manager(_FakeClient()).generate("p", on_token=explode) == WHOLE


def test_empty_chunks_are_skipped():
    class Sparse(_FakeClient):
        def chat(self, model, messages, stream, options):
            return iter(
                [
                    {"message": {"content": "FINDING\n"}},
                    {"message": {"content": ""}},
                    {"message": {}},
                    {"message": {"content": "done"}},
                ]
            )

    seen: list[str] = []
    text = _manager(Sparse()).generate("p", on_token=seen.append)
    assert text == "FINDING\ndone"
    assert seen == ["FINDING\n", "done"]


# ------------------------------------------------------------------
# Post-processing is unaffected
# ------------------------------------------------------------------

def test_parsing_a_streamed_answer_matches_an_unstreamed_one():
    parser = ResponseParser()

    plain = parser.parse_answer(
        _manager(_FakeClient()).generate("p"), num_evidence=6
    )
    streamed = parser.parse_answer(
        _manager(_FakeClient()).generate("p", on_token=lambda _: None),
        num_evidence=6,
    )

    assert streamed == plain
    assert streamed["citations"] == [1, 2]
    assert streamed["confidence"] == 60


def test_assessment_remains_extractable_from_streamed_text():
    """Calibration reads ASSESSMENT; streaming must not disturb it."""

    text = _manager(_FakeClient()).generate("p", on_token=lambda _: None)
    assert extract_assessment(text) == "Support is moderate."


# ------------------------------------------------------------------
# The prompt contract the parser depends on
# ------------------------------------------------------------------

@pytest.fixture()
def prompt() -> str:
    return PromptBuilder().build_answer_prompt(
        question="Any injection?", context="[1] plugin: windows.malfind"
    )


@pytest.fixture()
def flat(prompt: str) -> str:
    """The prompt with runs of whitespace collapsed.

    Instructions are hard-wrapped, so a phrase that reads as one sentence can
    straddle a newline. Asserting on the flattened text checks the wording
    rather than where the line happens to break.
    """

    return " ".join(prompt.split())


@pytest.mark.parametrize(
    "section", ["FINDING", "EVIDENCE", "ASSESSMENT", "GAPS"]
)
def test_the_four_sections_survive_the_prose_rewrite(prompt, section):
    assert section in prompt


def test_confidence_line_and_its_bands_survive(prompt):
    assert "CONFIDENCE: <0-100>" in prompt
    for band in ("80-95", "50-70", "25-45", "0-20"):
        assert band in prompt


def test_assessment_still_forbids_digits(flat):
    """A digit there would be parsed as the confidence value."""

    assert "Do NOT write any digits in this section" in flat


def test_prompt_protects_citation_bracket_syntax(flat):
    assert "Never put any other number in square brackets" in flat


def test_prompt_asks_for_depth_to_follow_the_question(flat):
    assert "Length should follow the question" in flat


def test_prompt_does_not_invite_external_links(prompt):
    """
    Evidence grounding forbids model-generated URLs: asked for a link, a model
    produces one whether or not it exists.
    """

    lowered = prompt.lower()
    for term in ("http://", "https://", "url", "link to", "github"):
        assert term not in lowered
