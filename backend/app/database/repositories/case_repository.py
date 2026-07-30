"""
Case Repository for the AI Memory Forensic Investigation Assistant.

Provides database operations specific to forensic cases.

Author:
    FIA Development Team
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.repositories.base_repository import BaseRepository
from app.models.case import Case

logger = get_logger(__name__)


class CaseRepository(BaseRepository[Case]):
    """
    Repository responsible for Case persistence.
    """

    def __init__(
        self,
        session: Session,
    ) -> None:
        super().__init__(
            session=session,
            model=Case,
        )

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_by_case_name(
        self,
        case_name: str,
    ) -> Case | None:
        """
        Return a case by its unique name.
        """

        statement = (
            select(Case)
            .where(Case.case_name == case_name)
        )

        return self.session.scalar(statement)

    def exists(
        self,
        case_name: str,
    ) -> bool:
        """
        Check whether a case already exists.
        """

        return (
            self.get_by_case_name(case_name)
            is not None
        )

    def list_active_cases(
        self,
    ) -> list[Case]:
        """
        Return all active cases.
        """

        statement = (
            select(Case)
            .where(Case.is_active.is_(True))
            .order_by(Case.created_at.desc())
        )

        return list(
            self.session.scalars(statement).all()
        )