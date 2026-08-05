"""
Chat Message Repository for the AI Memory Forensic Investigation Assistant.

Provides persistence operations for conversation history.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.repositories.base_repository import BaseRepository
from app.models.chat_message import ChatMessage

logger = get_logger(__name__)


class ChatMessageRepository(BaseRepository[ChatMessage]):
    """
    Repository responsible for ChatMessage persistence.
    """

    def __init__(
        self,
        session: Session,
    ) -> None:
        super().__init__(
            session=session,
            model=ChatMessage,
        )

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get_by_investigation(
        self,
        investigation_id: str,
    ) -> list[ChatMessage]:
        """
        Return the conversation history for an investigation.
        """

        statement = (
            select(ChatMessage)
            .where(
                ChatMessage.investigation_id == investigation_id
            )
            .order_by(
                ChatMessage.id.asc()
            )
        )

        return list(
            self.session.scalars(statement).all()
        )

    def count_by_role(
        self,
        role: str,
    ) -> int:
        """
        Return the number of messages with a given role.
        """

        statement = (
            select(
                func.count()
            )
            .select_from(ChatMessage)
            .where(
                ChatMessage.role == role
            )
        )

        return (
            self.session.scalar(statement)
            or 0
        )
