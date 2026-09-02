"""
Plugin Result Repository for the AI Memory Forensic Investigation Assistant.

Provides persistence operations for parsed Volatility plugin results.

Author:
    FIA Development Team
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.logging import get_logger
from app.database.repositories.base_repository import BaseRepository
from app.models.memory_dump import MemoryDump
from app.models.plugin_execution import PluginExecution
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

    def get_by_investigation(
        self,
        investigation_id: str,
    ) -> list[PluginResult]:
        """
        Return all evidence records belonging to an investigation.
        """

        statement = (
            select(PluginResult)
            .join(
                PluginExecution,
                PluginResult.plugin_execution_id == PluginExecution.id,
            )
            .join(
                MemoryDump,
                PluginExecution.memory_dump_id == MemoryDump.id,
            )
            .where(
                MemoryDump.investigation_id == investigation_id
            )
            .order_by(
                PluginResult.id.asc()
            )
        )

        return list(
            self.session.scalars(statement).all()
        )

    def stream_batch_by_investigation(
        self,
        investigation_id: str,
        after_id: int,
        limit: int,
    ) -> list[tuple]:
        """
        Return the next page of evidence for an investigation.

        Keyset pagination over the primary key keeps memory bounded for large
        investigations: only ``limit`` rows (and never the ORM identity map)
        are materialized. The plugin name is resolved in the same query so no
        per-row lazy load is issued.

        Parameters
        ----------
        investigation_id : str

        after_id : int
            Only rows with ``id`` strictly greater than this value are
            returned (start with 0).

        limit : int

        Returns
        -------
        list[tuple]
            Rows with ``id``, ``artifact_type``, ``artifact_name``,
            ``artifact_value``, ``confidence_score``, and ``plugin_name``.
        """

        statement = (
            select(
                PluginResult.id,
                PluginResult.artifact_type,
                PluginResult.artifact_name,
                PluginResult.artifact_value,
                PluginResult.confidence_score,
                PluginExecution.plugin_name,
            )
            .join(
                PluginExecution,
                PluginResult.plugin_execution_id == PluginExecution.id,
            )
            .join(
                MemoryDump,
                PluginExecution.memory_dump_id == MemoryDump.id,
            )
            .where(
                MemoryDump.investigation_id == investigation_id
            )
            .where(
                PluginResult.id > after_id
            )
            .order_by(
                PluginResult.id.asc()
            )
            .limit(limit)
        )

        return list(
            self.session.execute(statement).all()
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

        statement = (
            select(
                func.count()
            )
            .select_from(PluginResult)
            .where(
                PluginResult.plugin_execution_id == execution_id
            )
        )

        return (
            self.session.scalar(statement)
            or 0
        )

    def count_by_investigation(
        self,
        investigation_id: str,
    ) -> int:
        """
        Return the number of evidence records for an investigation.

        This is the authoritative proof that forensic evidence exists even
        when the vector store is empty: zero Chroma vectors must never be
        interpreted as zero evidence.
        """

        statement = (
            select(
                func.count()
            )
            .select_from(PluginResult)
            .join(
                PluginExecution,
                PluginResult.plugin_execution_id == PluginExecution.id,
            )
            .join(
                MemoryDump,
                PluginExecution.memory_dump_id == MemoryDump.id,
            )
            .where(
                MemoryDump.investigation_id == investigation_id
            )
        )

        return (
            self.session.scalar(statement)
            or 0
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

    # ------------------------------------------------------------------
    # Filtered Search
    # ------------------------------------------------------------------

    _SORT_COLUMNS = {
        "id": PluginResult.id,
        "artifact_type": PluginResult.artifact_type,
        "artifact_name": PluginResult.artifact_name,
        "created_at": PluginResult.created_at,
    }

    def _base_statement(
        self,
        investigation_id: str | None = None,
    ) -> Any:
        """
        Build a filtered query joining results to their investigation.
        """

        statement = (
            select(PluginResult)
            .options(
                selectinload(PluginResult.plugin_execution)
            )
            .join(
                PluginExecution,
                PluginResult.plugin_execution_id == PluginExecution.id,
            )
            .join(
                MemoryDump,
                PluginExecution.memory_dump_id == MemoryDump.id,
            )
        )

        if investigation_id:
            statement = statement.where(
                MemoryDump.investigation_id == investigation_id
            )

        return statement

    @staticmethod
    def _severity_condition(
        severity: str,
    ) -> Any:
        """
        Translate a severity label into a persisted risk level predicate.

        The filter operates on the classifier's ``risk_level`` column
        (not the confidence score). Records that were never classified
        (NULL ``risk_level``) do not match any severity filter.
        """

        if severity in {"high", "medium", "low", "unknown", "insufficient-evidence"}:
            return PluginResult.risk_level == severity

        return None

    def search(
        self,
        investigation_id: str | None = None,
        plugin: str | None = None,
        artifact_type: str | None = None,
        severity: str | None = None,
        search: str | None = None,
        sort_by: str = "id",
        sort_order: str = "desc",
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[PluginResult], int]:
        """
        Return evidence matching the provided filters plus the total count.
        """

        statement = self._base_statement(
            investigation_id=investigation_id,
        )

        if plugin:
            statement = statement.where(
                PluginExecution.plugin_name == plugin
            )

        if artifact_type:
            statement = statement.where(
                PluginResult.artifact_type == artifact_type
            )

        severity_condition = self._severity_condition(severity) if severity else None

        if severity_condition is not None:
            statement = statement.where(severity_condition)

        if search:
            like = f"%{search}%"
            statement = statement.where(
                or_(
                    PluginResult.artifact_name.ilike(like),
                    PluginResult.artifact_type.ilike(like),
                    PluginResult.artifact_value.ilike(like),
                )
            )

        subquery = statement.subquery()

        count_statement = select(
            func.count()
        ).select_from(subquery)

        total = self.session.scalar(count_statement) or 0

        sort_column = self._SORT_COLUMNS.get(
            sort_by,
            PluginResult.id,
        )

        if sort_order == "asc":
            statement = statement.order_by(sort_column.asc())
        else:
            statement = statement.order_by(sort_column.desc())

        offset = (page - 1) * page_size

        statement = statement.offset(offset).limit(page_size)

        return (
            list(self.session.scalars(statement).all()),
            total,
        )

    def get_plugin_names(
        self,
        investigation_id: str | None = None,
    ) -> list[str]:
        """
        Return the distinct plugin names (optionally for an investigation).
        """

        statement = (
            select(PluginExecution.plugin_name)
            .join(
                PluginResult,
                PluginResult.plugin_execution_id == PluginExecution.id,
            )
            .join(
                MemoryDump,
                PluginExecution.memory_dump_id == MemoryDump.id,
            )
            .distinct()
            .order_by(PluginExecution.plugin_name)
        )

        if investigation_id:
            statement = statement.where(
                MemoryDump.investigation_id == investigation_id
            )

        return list(
            self.session.scalars(statement).all()
        )

    def get_artifact_types(
        self,
        investigation_id: str | None = None,
    ) -> list[str]:
        """
        Return the distinct artifact types (optionally for an investigation).
        """

        statement = (
            select(PluginResult.artifact_type)
            .join(
                PluginExecution,
                PluginResult.plugin_execution_id == PluginExecution.id,
            )
            .join(
                MemoryDump,
                PluginExecution.memory_dump_id == MemoryDump.id,
            )
            .distinct()
            .order_by(PluginResult.artifact_type)
        )

        if investigation_id:
            statement = statement.where(
                MemoryDump.investigation_id == investigation_id
            )

        return list(
            self.session.scalars(statement).all()
        )

    def get_artifact_type_distribution(
        self,
        limit: int = 8,
    ) -> list[tuple]:
        """
        Return the most common artifact types with their counts.
        """

        statement = (
            select(
                PluginResult.artifact_type,
                func.count(PluginResult.id),
            )
            .group_by(PluginResult.artifact_type)
            .order_by(
                func.count(PluginResult.id).desc()
            )
            .limit(limit)
        )

        return list(
            self.session.execute(statement).all()
        )

    def get_severity_distribution(
        self,
    ) -> list[tuple]:
        """
        Return evidence counts grouped by classified risk level.

        Records whose ``risk_level`` is NULL have not been classified yet
        and are reported under ``"unclassified"`` rather than dropped, so
        the total always reconciles with the overall evidence count.
        """

        statement = (
            select(
                func.coalesce(
                    PluginResult.risk_level,
                    "unclassified",
                ).label("severity"),
                func.count(PluginResult.id).label("count"),
            )
            .group_by("severity")
            .order_by(func.count(PluginResult.id).desc())
        )

        return list(
            self.session.execute(statement).all()
        )

    def list_investigations(
        self,
    ) -> list[tuple]:
        """
        Return aggregated summaries for every investigation.
        """

        statement = (
            select(
                MemoryDump.investigation_id,
                MemoryDump.filename,
                MemoryDump.status,
                MemoryDump.progress,
                MemoryDump.uploaded_at,
                func.count(PluginResult.id).label("evidence_count"),
                func.count(
                    func.distinct(
                        case(
                            (
                                PluginResult.id.is_not(None),
                                PluginExecution.plugin_name,
                            ),
                            else_=None,
                        )
                    )
                ).label("plugin_count"),
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
        )

        return list(
            self.session.execute(statement).all()
        )