"""
Generic Base Repository for the AI Memory Forensic Investigation Assistant.

Provides reusable CRUD operations for SQLAlchemy ORM models.

Author:
    FIA Development Team
"""

from __future__ import annotations

from typing import Generic, TypeVar

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger

logger = get_logger(__name__)

ModelType = TypeVar("ModelType")


class BaseRepository(Generic[ModelType]):
    """
    Generic repository implementing common CRUD operations.
    """

    def __init__(
        self,
        session: Session,
        model: type[ModelType],
    ) -> None:
        self._session = session
        self._model = model

    @property
    def session(self) -> Session:
        return self._session

    @property
    def model(self) -> type[ModelType]:
        return self._model

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create(
        self,
        entity: ModelType,
    ) -> ModelType:
        """
        Persist a new entity.
        """

        self.session.add(entity)
        self.session.commit()
        self.session.refresh(entity)

        logger.info(
            "%s created successfully.",
            self.model.__name__,
        )

        return entity

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_by_id(
        self,
        entity_id: int,
    ) -> ModelType | None:
        """
        Retrieve an entity by primary key.
        """

        return self.session.get(
            self.model,
            entity_id,
        )

    def get_all(self) -> list[ModelType]:
        """
        Return all entities.
        """

        statement = select(self.model)

        return list(
            self.session.scalars(statement).all()
        )

    def count(self) -> int:
        """
        Return the total number of entities.
        """

        statement = select(
            func.count()
        ).select_from(self.model)

        return (
            self.session.scalar(statement)
            or 0
        )

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def update(
        self,
        entity: ModelType,
    ) -> ModelType:
        """
        Commit modifications to an entity.
        """

        self.session.commit()
        self.session.refresh(entity)

        logger.info(
            "%s updated successfully.",
            self.model.__name__,
        )

        return entity

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete(
        self,
        entity: ModelType,
    ) -> None:
        """
        Delete an entity.
        """

        self.session.delete(entity)
        self.session.commit()

        logger.info(
            "%s deleted successfully.",
            self.model.__name__,
        )