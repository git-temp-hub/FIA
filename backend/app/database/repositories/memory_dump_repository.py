"""
Memory Dump Repository for the AI Memory Forensic Investigation Assistant.

Provides persistence operations specific to memory dumps.

Author:
    FIA Development Team
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.repositories.base_repository import BaseRepository
from app.models.memory_dump import MemoryDump
from app.models.plugin_execution import PluginExecution
from app.models.plugin_result import PluginResult

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

    def get_by_investigation_id(
        self,
        investigation_id: str,
    ) -> MemoryDump | None:
        """
        Return a memory dump by investigation identifier.
        """

        statement = (
            select(MemoryDump)
            .where(MemoryDump.investigation_id == investigation_id)
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
            .order_by(MemoryDump.uploaded_at.desc())
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

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def list_recent_with_evidence(
        self,
        limit: int = 5,
    ) -> list[tuple]:
        """
        Return recent investigations with their evidence counts.
        """

        statement = (
            select(
                MemoryDump.investigation_id,
                MemoryDump.filename,
                MemoryDump.status,
                MemoryDump.progress,
                MemoryDump.uploaded_at,
                func.count(PluginResult.id).label(
                    "evidence_count"
                ),
            )
            .select_from(MemoryDump)
            .outerjoin(
                PluginExecution,
                PluginExecution.memory_dump_id == MemoryDump.id,
            )
            .outerjoin(
                PluginResult,
                PluginResult.plugin_execution_id == PluginExecution.id,
            )
            .group_by(MemoryDump.id)
            .order_by(MemoryDump.uploaded_at.desc())
            .limit(limit)
        )

        return list(
            self.session.execute(statement).all()
        )

    def count_by_day(
        self,
        days: int = 7,
    ) -> list[tuple]:
        """
        Return the number of investigations created per day for
        the last ``days`` days.
        """

        start = (
            datetime.utcnow()
            - timedelta(days=days - 1)
        ).replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
        )

        statement = (
            select(
                func.date(MemoryDump.uploaded_at),
                func.count(MemoryDump.id),
            )
            .where(
                MemoryDump.uploaded_at >= start
            )
            .group_by(
                func.date(MemoryDump.uploaded_at)
            )
            .order_by(
                func.date(MemoryDump.uploaded_at)
            )
        )

        return list(
            self.session.execute(statement).all()
        )