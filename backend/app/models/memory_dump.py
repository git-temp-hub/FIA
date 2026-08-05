"""
Memory Dump Model for the AI Memory Forensic Investigation Assistant.

This module defines the MemoryDump entity, representing a memory image
uploaded for forensic investigation.

Author:
    FIA Development Team
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from app.database.database import Base

class MemoryDump(Base):
    """
    ORM model representing a forensic memory dump.

    Each memory dump belongs to a single investigation case and serves
    as the parent entity for Volatility plugin executions.
    """

    __tablename__ = "memory_dumps"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    case_id: Mapped[int] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    original_path: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
    )

    stored_path: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
    )

    sha256_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    investigation_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    operating_system: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    architecture: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    file_size: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="uploaded",
        nullable=False,
    )

    progress: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    volatility_profile: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    notes: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
    )

    case: Mapped["Case"] = relationship(
        "Case",
        back_populates="memory_dumps",
    )
    plugin_executions: Mapped[list["PluginExecution"]] = relationship(
    "PluginExecution",
    back_populates="memory_dump",
    cascade="all, delete-orphan",
)

    def __repr__(self) -> str:
        """
        Return a readable representation of the MemoryDump object.
        """

        return (
            f"MemoryDump("
            f"id={self.id}, "
            f"filename='{self.filename}', "
            f"status='{self.status}'"
            f")"
        )


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "MemoryDump",
]