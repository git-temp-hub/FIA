"""
Chat API

Evidence-backed AI question answering with per-investigation
conversation history.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
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
