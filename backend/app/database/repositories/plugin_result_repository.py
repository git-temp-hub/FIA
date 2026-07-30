"""
Plugin Result Repository for the AI Memory Forensic Investigation Assistant.

Provides persistence operations for parsed Volatility plugin results.

Author:
    FIA Development Team
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.repositories.base_repository import BaseRepository
from app.models.plugin_result import PluginResult

logger = get_logger(__name__)


class PluginResultRepository(BaseRepository[PluginResult]):
    """
    Repository responsible for PluginResult persistence.
    """

    def __init__(
        self,
        session: Session,
    ) -> None:
        super().__init__(
            session=session,
            model=PluginResult,
        )

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get_by_execution(
        self,
        execution_id: int,
    ) -> list[PluginResult]:
        """
        Return all parsed results for a plugin execution.
        """

        statement = (
            select(PluginResult)
            .where(
                PluginResult.plugin_execution_id == execution_id
            )
            .order_by(
                PluginResult.id.asc()
            )
        )

        return list(
            self.session.scalars(statement).all()
        )

    def get_by_artifact_type(
        self,
        artifact_type: str,
    ) -> list[PluginResult]:
        """
        Return all results of a specific artifact type.
        """

        statement = (
            select(PluginResult)
            .where(
                PluginResult.artifact_type == artifact_type
            )
        )

        return list(
            self.session.scalars(statement).all()
        )

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def count_by_execution(
        self,
        execution_id: int,
    ) -> int:
        """
        Return the number of parsed rows for an execution.
        """

        return len(
            self.get_by_execution(execution_id)
        )

    def has_results(
        self,
        execution_id: int,
    ) -> bool:
        """
        Check whether parsed results exist.
        """

        return (
            self.count_by_execution(execution_id)
            > 0
        )