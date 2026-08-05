"""
Report Model for the AI Memory Forensic Investigation Assistant.

This module defines the Report entity, representing a generated
forensic investigation report (PDF) with its stored metadata.
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
# Report Model
# ==============================================================================


class Report(Base):
    """
    Represents a generated investigation report.

    Each report is produced for exactly one investigation and stores
    the metadata required to list, view, and download the PDF file.
    """

    __tablename__ = "reports"

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

    case_name: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )

    dump_filename: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    sha256_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    file_path: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
    )

    file_size: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="generated",
        nullable=False,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    generated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    # ==========================================================================
    # Object Representation
    # ==========================================================================

    def __repr__(self) -> str:
        """
        Return a readable representation of the Report object.
        """

        return (
            f"Report("
            f"id={self.id}, "
            f"investigation_id='{self.investigation_id}', "
            f"filename='{self.filename}', "
            f"status='{self.status}'"
            f")"
        )


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "Report",
]
