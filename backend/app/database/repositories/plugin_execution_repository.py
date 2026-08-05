"""
Plugin Execution Repository for the AI Memory Forensic Investigation Assistant.

Provides persistence operations for Volatility plugin executions.

Author:
    FIA Development Team
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.repositories.base_repository import BaseRepository
from app.models.plugin_execution import PluginExecution

logger = get_logger(__name__)


class PluginExecutionRepository(BaseRepository[PluginExecution]):
    """
    Repository responsible for PluginExecution persistence.
    """

    def __init__(
        self,
        session: Session,
    ) -> None:
        super().__init__(
            session=session,
            model=PluginExecution,
        )

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get_by_memory_dump(
        self,
        memory_dump_id: int,
    ) -> list[PluginExecution]:
        """
        Return all plugin executions for a memory dump.
        """

        statement = (
            select(PluginExecution)
            .where(
                PluginExecution.memory_dump_id == memory_dump_id
            )
            .order_by(
                PluginExecution.executed_at.desc()
            )
        )

        return list(
            self.session.scalars(statement).all()
        )

    def get_by_plugin(
        self,
        plugin_name: str,
    ) -> list[PluginExecution]:
        """
        Return all executions of a specific plugin.
        """

        statement = (
            select(PluginExecution)
            .where(
                PluginExecution.plugin_name == plugin_name
            )
            .order_by(
                PluginExecution.executed_at.desc()
            )
        )

        return list(
            self.session.scalars(statement).all()
        )

    # ------------------------------------------------------------------
    # Status Queries
    # ------------------------------------------------------------------

    def get_running(
        self,
    ) -> list[PluginExecution]:
        """
        Return currently running plugin executions.
        """

        statement = (
            select(PluginExecution)
            .where(
                PluginExecution.execution_status == "running"
            )
        )

        return list(
            self.session.scalars(statement).all()
        )

    def get_completed(
        self,
    ) -> list[PluginExecution]:
        """
        Return completed executions.
        """

        statement = (
            select(PluginExecution)
            .where(
                PluginExecution.execution_status == "completed"
            )
        )

        return list(
            self.session.scalars(statement).all()
        )

    def get_failed(
        self,
    ) -> list[PluginExecution]:
        """
        Return failed executions.
        """

        statement = (
            select(PluginExecution)
            .where(
                PluginExecution.execution_status == "failed"
            )
        )

        return list(
            self.session.scalars(statement).all()
        )

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def execution_stats(
        self,
    ) -> dict[str, int]:
        """
        Return the number of executions grouped by status.
        """

        statement = (
            select(
                PluginExecution.execution_status,
                func.count(PluginExecution.id),
            )
            .group_by(
                PluginExecution.execution_status
            )
        )

        return {
            status: count
            for status, count in
            self.session.execute(statement).all()
        }