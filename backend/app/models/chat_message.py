"""
Chat Message Model for the AI Memory Forensic Investigation Assistant.

This module defines the ChatMessage entity, representing a single
message in a per-investigation AI conversation.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from app.database.database import Base

# ==============================================================================
# Chat Message Model
# ==============================================================================


class ChatMessage(Base):
    """
    Represents one message in an investigation's AI conversation.
    """

    __tablename__ = "chat_messages"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    investigation_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    role: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    citations: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    confidence: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    # ==========================================================================
    # Object Representation
    # ==========================================================================

    def __repr__(self) -> str:
        """
        Return a readable representation of the ChatMessage object.
        """

        return (
            f"ChatMessage("
            f"id={self.id}, "
            f"investigation_id='{self.investigation_id}', "
            f"role='{self.role}'"
            f")"
        )

# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "ChatMessage",
]
