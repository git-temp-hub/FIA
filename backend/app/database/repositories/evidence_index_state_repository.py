"""
Evidence Index State Repository for the AI Memory Forensic Investigation Assistant.

Persistence operations for ``EvidenceIndexState``. This repository backs the
incremental RAG indexer: it tracks which evidence rows have been embedded and
the content hash behind each vector, enabling skip-on-rerun and crash-resume.

Author:
    FIA Development Team
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.repositories.base_repository import BaseRepository
from app.models.evidence_index_state import EvidenceIndexState

logger = get_logger(__name__)


class EvidenceIndexStateRepository(BaseRepository[EvidenceIndexState]):
    """
    Repository responsible for EvidenceIndexState persistence.
    """

    def __init__(
        self,
        session: Session,
    ) -> None:
        super().__init__(
            session=session,
            model=EvidenceIndexState,
        )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_by_investigation(
        self,
        investigation_id: str,
    ) -> dict[int, str]:
        """
        Return the indexed content hashes for an investigation.

        Returns
        -------
        dict
            Mapping of ``evidence_id`` to the persisted ``content_hash``.
        """

        statement = (
            select(
                EvidenceIndexState.evidence_id,
                EvidenceIndexState.content_hash,
            )
            .where(
                EvidenceIndexState.investigation_id == investigation_id
            )
        )

        return {
            row.evidence_id: row.content_hash
            for row in self.session.execute(statement).all()
        }

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def upsert_many(
        self,
        investigation_id: str,
        evidence_ids: list[int],
        content_hashes: list[str],
    ) -> None:
        """
        Insert or refresh index-state rows for a batch of evidence.

        Uses a single SQLite ``INSERT ... ON CONFLICT DO UPDATE`` so the
        checkpoint is cheap and idempotent: re-running after an interrupted
        index simply refreshes the same rows.

        Commits the batch so the index is resumable after each page.
        """

        if not evidence_ids:
            return

        timestamp = datetime.utcnow()

        statement = insert(EvidenceIndexState).on_conflict_do_update(
            index_elements=[EvidenceIndexState.evidence_id],
            set_={
                "content_hash": insert(EvidenceIndexState).excluded.content_hash,
                "indexed_at": insert(EvidenceIndexState).excluded.indexed_at,
            },
        )

        rows = [
            {
                "evidence_id": evidence_id,
                "investigation_id": investigation_id,
                "content_hash": content_hash,
                "indexed_at": timestamp,
            }
            for evidence_id, content_hash in zip(
                evidence_ids,
                content_hashes,
            )
        ]

        self.session.execute(statement, rows)
        self.session.commit()

        logger.info(
            "Recorded index state for %d evidence rows of investigation '%s'.",
            len(rows),
            investigation_id,
        )

    def delete_by_evidence_ids(
        self,
        evidence_ids: list[int],
    ) -> int:
        """
        Remove index-state rows for evidence rows that no longer exist.
        """

        if not evidence_ids:
            return 0

        statement = delete(EvidenceIndexState).where(
            EvidenceIndexState.evidence_id.in_(evidence_ids)
        )

        result = self.session.execute(statement)
        self.session.commit()

        return result.rowcount or 0


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "EvidenceIndexStateRepository",
]