"""
Memory Dump Repository for the AI Memory Forensic Investigation Assistant.

Provides persistence operations specific to memory dumps.

Author:
    FIA Development Team
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.repositories.base_repository import BaseRepository
from app.models.memory_dump import MemoryDump

logger = get_logger(__name__)


class MemoryDumpRepository(BaseRepository[MemoryDump]):
    """
    Repository responsible for MemoryDump persistence.
    """

    def __init__(
        self,
        session: Session,
    ) -> None:
        super().__init__(
            session=session,
            model=MemoryDump,
        )

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get_by_sha256(
        self,
        sha256: str,
    ) -> MemoryDump | None:
        """
        Return a memory dump by SHA-256 hash.
        """

        statement = (
            select(MemoryDump)
            .where(MemoryDump.sha256_hash == sha256)
        )

        return self.session.scalar(statement)

    def get_by_filename(
        self,
        filename: str,
    ) -> MemoryDump | None:
        """
        Return a memory dump by filename.
        """

        statement = (
            select(MemoryDump)
            .where(MemoryDump.filename == filename)
        )

        return self.session.scalar(statement)

    # ------------------------------------------------------------------
    # Case Queries
    # ------------------------------------------------------------------

    def get_by_case(
        self,
        case_id: int,
    ) -> list[MemoryDump]:
        """
        Return all dumps belonging to a case.
        """

        statement = (
            select(MemoryDump)
            .where(MemoryDump.case_id == case_id)
            .order_by(MemoryDump.created_at.desc())
        )

        return list(
            self.session.scalars(statement).all()
        )

    # ------------------------------------------------------------------
    # Duplicate Detection
    # ------------------------------------------------------------------

    def exists_hash(
        self,
        sha256: str,
    ) -> bool:
        """
        Check whether a dump with this SHA-256 already exists.
        """

        return (
            self.get_by_sha256(sha256)
            is not None
        )

    def exists_filename(
        self,
        filename: str,
    ) -> bool:
        """
        Check whether a filename already exists.
        """

        return (
            self.get_by_filename(filename)
            is not None
        )