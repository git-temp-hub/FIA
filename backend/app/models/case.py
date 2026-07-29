"""
Case Model for the AI Memory Forensic Investigation Assistant.

This module defines the Case entity, representing a single forensic
investigation within the FIA platform.

Author:
    FIA Development Team
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from app.database.database import Base

# ==============================================================================
# Case Model
# ==============================================================================


class Case(Base):
    """
    Represents a forensic investigation case.

    A Case is the top-level entity within the FIA platform.
    Every memory dump, plugin execution, and forensic artifact
    belongs to exactly one Case.
    """

    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    case_name: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )

    investigator: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    # ==========================================================================
    # Relationships
    # ==========================================================================

    memory_dumps = relationship(
        "MemoryDump",
        back_populates="case",
        cascade="all, delete-orphan",
    )

    # ==========================================================================
    # Object Representation
    # ==========================================================================

    def __repr__(self) -> str:
        """
        Return a readable representation of the Case object.
        """

        return (
            f"Case("
            f"id={self.id}, "
            f"case_name='{self.case_name}', "
            f"investigator='{self.investigator}'"
            f")"
        )

# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "Case",
]