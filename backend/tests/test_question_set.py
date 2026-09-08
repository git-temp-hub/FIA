"""
Tests for the department question set and its routing.

Routing is checked here rather than only in the harness so a rephrasing that
silently changes which evidence is searched fails in CI, not an hour into a
batch run.
"""

from __future__ import annotations

import pytest

from app.services.question_routing import ROUTES, match_route
from app.services.question_set import QUESTIONS


def test_all_twenty_questions_are_present():
    assert len(QUESTIONS) == 20
    assert [entry.qid for entry in QUESTIONS] == [
        f"Q{number}" for number in range(1, 21)
    ]


@pytest.mark.parametrize("entry", QUESTIONS, ids=lambda entry: entry.qid)
def test_question_reaches_its_intended_route(entry):
    """
    An answer drawn from the wrong evidence can still read well, so routing is
    verified before any answer is judged.
    """
    route = match_route(entry.question)
    assert route is not None, f"{entry.qid} matched no route"
    assert route.qid == entry.expected


def test_every_route_has_a_question():
    """A route nothing reaches is untested surface."""
    covered = {entry.expected for entry in QUESTIONS}
    assert covered == {route.qid for route in ROUTES}


def test_questions_are_distinct():
    texts = [entry.question.lower() for entry in QUESTIONS]
    assert len(set(texts)) == len(texts)
