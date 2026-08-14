"""
Evidence Index State Model for the AI Memory Forensic Investigation Assistant.

Records which ``plugin_results`` rows have already been embedded into the
vector database and the content hash backing each vector, so indexing is
incremental: unchanged evidence is never re-embedded and interrupted runs
resume from the last committed checkpoint.

SQLite (``plugin_results``) remains the authoritative evidence source; this
table only tracks index state, never evidence content.

Author:
    FIA Development Team
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import UniqueConstraint
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from app.database.database import Base

# ==============================================================================
# Evidence Index State Model
# ==============================================================================


class EvidenceIndexState(Base):
    """
    Tracks the indexed state of a single evidence row.

    A row is present here once its vector has been written to ChromaDB.
    ``content_hash`` is the SHA-256 of the exact indexed document; when the
    underlying evidence changes the hash changes and the row is re-embedded.
    """

    __tablename__ = "evidence_index_state"

    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "evidence_id",
            name="uq_evidence_index_state_investigation_evidence",
        ),
    )

    evidence_id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    investigation_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    content_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    indexed_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    def __repr__(self) -> str:
        """
        Return a readable representation of the index state record.
        """

        return (
            f"EvidenceIndexState("
            f"evidence_id={self.evidence_id}, "
            f"investigation_id='{self.investigation_id}'"
            f")"
        )


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "EvidenceIndexState",
]