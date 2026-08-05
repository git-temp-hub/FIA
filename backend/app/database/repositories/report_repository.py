"""
Report Repository for the AI Memory Forensic Investigation Assistant.

Provides persistence operations for generated investigation reports.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.repositories.base_repository import BaseRepository
from app.models.report import Report

logger = get_logger(__name__)


class ReportRepository(BaseRepository[Report]):
    """
    Repository responsible for Report persistence.
    """

    def __init__(
        self,
        session: Session,
    ) -> None:
        super().__init__(
            session=session,
            model=Report,
        )

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get_all_ordered(
        self,
    ) -> list[Report]:
        """
        Return every report, newest first.
        """

        statement = (
            select(Report)
            .order_by(Report.generated_at.desc())
        )

        return list(
            self.session.scalars(statement).all()
        )

    def get_by_investigation(
        self,
        investigation_id: str,
    ) -> list[Report]:
        """
        Return every report for an investigation, newest first.
        """

        statement = (
            select(Report)
            .where(Report.investigation_id == investigation_id)
            .order_by(Report.generated_at.desc())
        )

        return list(
            self.session.scalars(statement).all()
        )
