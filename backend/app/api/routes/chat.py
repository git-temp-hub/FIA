"""
Chat API

Evidence-backed AI question answering with per-investigation
conversation history.
"""

from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.database import get_db
from app.database.repositories import (
    ChatMessageRepository,
    MemoryDumpRepository,
)
from app.models.chat_message import ChatMessage
from app.schemas.chat import (
    ChatHistoryMessage,
    ChatHistoryResponse,
    ChatQueryRequest,
    ChatQueryResponse,
    EvidenceReference,
)
from app.services.ai_investigation_service import (
    ai_investigation_service,
)

logger = get_logger(__name__)

router = APIRouter(
    prefix="/chat",
    tags=["Chat"],
)


def _reference_from_dict(
    index: int,
    reference: dict,
) -> EvidenceReference:
    """
    Build an EvidenceReference from a stored citation dict.
    """

    return EvidenceReference(
        index=index,
        evidence_id=reference.get("evidence_id"),
        plugin_name=reference.get("plugin_name"),
        artifact_type=reference.get("artifact_type"),
        confidence_score=reference.get("confidence_score"),
        document=reference.get("document", ""),
        score=reference.get("score"),
    )


def _persist_exchange(
    db: Session,
    request: ChatQueryRequest,
    result: dict,
) -> None:
    """
    Save the question and the finished answer to conversation history.

    Only ever called with a completed result, so history holds the same
    post-processed answer and confidence the client is shown -- never a
    partial stream.
    """

    chat_repository = ChatMessageRepository(db)

    chat_repository.create(
        ChatMessage(
            investigation_id=request.investigation_id,
            session_id=request.session_id,
            role="user",
            content=request.question,
        )
    )

    chat_repository.create(
        ChatMessage(
            investigation_id=request.investigation_id,
            session_id=request.session_id,
            role="assistant",
            content=result["answer"],
            citations=json.dumps(result["citations"]),
            confidence=result["confidence"],
        )
    )


@router.post(
    "/query",
    response_model=ChatQueryResponse,
)
async def chat_query(
    request: ChatQueryRequest,
    db: Session = Depends(get_db),
):
    """
    Ask a question about an investigation and receive an
    evidence-backed answer.
    """

    memory_dump_repository = MemoryDumpRepository(db)

    investigation = (
        memory_dump_repository.get_by_investigation_id(
            request.investigation_id
        )
    )

    if investigation is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found.",
        )

    try:
        result = ai_investigation_service.answer(
            investigation_id=request.investigation_id,
            question=request.question,
            top_k=request.top_k,
            db=db,
        )
    except RuntimeError as exc:
        logger.exception(
            "AI query failed for investigation '%s'.",
            request.investigation_id,
        )
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from exc

    _persist_exchange(db, request, result)

    citations = [
        _reference_from_dict(index + 1, reference)
        for index, reference in enumerate(result["citations"])
    ]

    references = [
        _reference_from_dict(index + 1, reference)
        for index, reference in enumerate(result["references"])
    ]

    return ChatQueryResponse(
        investigation_id=request.investigation_id,
        session_id=request.session_id,
        question=result["question"],
        answer=result["answer"],
        confidence=result["confidence"],
        insufficient=result["insufficient"],
        citations=citations,
        references=references,
    )


def _sse(event: str, payload: dict) -> str:
    """Encode one server-sent event."""

    return "event: {0}\ndata: {1}\n\n".format(event, json.dumps(payload))


@router.post("/stream")
async def chat_stream(
    request: ChatQueryRequest,
    db: Session = Depends(get_db),
):
    """
    Ask a question and receive the answer as it is generated.

    Streaming is a delivery change only. The model's raw output is forwarded
    chunk by chunk as ``token`` events so the answer appears progressively,
    while the complete text is accumulated server-side and put through the
    identical post-processing as the non-streaming route: citation parsing,
    confidence calibration, signature corroboration and the malfind ceiling.

    Those mechanisms can only run once the text is whole -- a confidence
    ceiling cannot be applied to half an answer, and a corroboration notice
    appended mid-stream would be attached to an answer that had not yet made
    its claim. So they are never applied to the stream. Everything they
    produce arrives in a single terminal ``result`` event carrying the
    authoritative answer, confidence and citations, which the client uses to
    replace what it rendered while streaming.

    A client that ignores ``token`` events and reads only ``result`` receives
    exactly what ``POST /chat/query`` returns.
    """

    memory_dump_repository = MemoryDumpRepository(db)

    if memory_dump_repository.get_by_investigation_id(
        request.investigation_id
    ) is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found.",
        )

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()

    def on_token(chunk: str) -> None:
        # Called from the worker thread; hop back onto the event loop.
        loop.call_soon_threadsafe(queue.put_nowait, ("token", chunk))

    def run() -> dict:
        return ai_investigation_service.answer(
            investigation_id=request.investigation_id,
            question=request.question,
            top_k=request.top_k,
            db=db,
            on_token=on_token,
        )

    async def events() -> AsyncIterator[str]:

        # Retrieval, coverage assessment and the deterministic scans all run
        # before the model is called, and on a large investigation that is a
        # majority of the wait -- measured at 75s of 132s. Announcing the
        # phase turns a blank spinner into something legible.
        yield _sse("status", {"phase": "retrieving"})

        task = asyncio.create_task(asyncio.to_thread(run))

        announced = False

        while True:

            drain = asyncio.create_task(queue.get())
            done, _ = await asyncio.wait(
                {drain, task},
                return_when=asyncio.FIRST_COMPLETED,
            )

            if drain in done:
                kind, chunk = drain.result()

                if not announced:
                    announced = True
                    yield _sse("status", {"phase": "generating"})

                yield _sse(kind, {"text": chunk})
                continue

            drain.cancel()

            # The worker finished; forward anything still queued before the
            # terminal event so no generated text is dropped.
            while not queue.empty():
                kind, chunk = queue.get_nowait()
                yield _sse(kind, {"text": chunk})

            break

        try:
            result = await task
        except RuntimeError as exc:
            logger.exception(
                "Streamed AI query failed for investigation '%s'.",
                request.investigation_id,
            )
            yield _sse("error", {"detail": str(exc)})
            return

        _persist_exchange(db, request, result)

        yield _sse(
            "result",
            {
                "investigation_id": request.investigation_id,
                "session_id": request.session_id,
                "question": result["question"],
                "answer": result["answer"],
                "confidence": result["confidence"],
                "insufficient": result["insufficient"],
                "citations": [
                    _reference_from_dict(index + 1, reference).model_dump()
                    for index, reference in enumerate(result["citations"])
                ],
            },
        )

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get(
    "/history/{investigation_id}",
    response_model=ChatHistoryResponse,
)
async def chat_history(
    investigation_id: str,
    session_id: str | None = None,
    db: Session = Depends(get_db),
):
    """
    Return the saved conversation history for an investigation session.
    """

    chat_repository = ChatMessageRepository(db)

    messages = chat_repository.get_by_investigation(
        investigation_id,
        session_id=session_id,
    )

    history: list[ChatHistoryMessage] = []

    for message in messages:

        citations: list[EvidenceReference] | None = None

        if message.citations:
            try:
                citations = [
                    _reference_from_dict(index + 1, reference)
                    for index, reference in enumerate(
                        json.loads(message.citations)
                    )
                ]
            except json.JSONDecodeError:
                logger.warning(
                    "Invalid citations JSON on message %d.",
                    message.id,
                )
                citations = None

        history.append(
            ChatHistoryMessage(
                id=message.id,
                role=message.role,
                content=message.content,
                citations=citations,
                confidence=message.confidence,
                created_at=message.created_at,
            )
        )

    return ChatHistoryResponse(
        investigation_id=investigation_id,
        session_id=session_id,
        messages=history,
    )
