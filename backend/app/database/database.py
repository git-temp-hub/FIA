"""
Database Manager for the AI Memory Forensic Investigation Assistant (FIA).

This module provides the centralized SQLAlchemy database configuration,
engine creation, session management, and database initialization for
the FIA backend.

All application modules should obtain database sessions through this
module rather than creating their own database connections.

Author:
    FIA Development Team
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


# ==============================================================================
# Database Path
# ==============================================================================

DATABASE_PATH: Path = settings.database.path

DATABASE_URL = f"sqlite:///{DATABASE_PATH.as_posix()}"

# ==============================================================================
# SQLAlchemy Engine
# ==============================================================================

engine: Engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    future=True,
    echo=False,
)


# ==============================================================================
# Session Factory
# ==============================================================================

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    class_=Session,
)


# ==============================================================================
# Declarative Base
# ==============================================================================


class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy ORM models.

    Every database model within the FIA application must inherit
    from this class.
    """

    pass

# ==============================================================================
# Database Manager
# ==============================================================================


class DatabaseManager:
    """
    Centralized database manager.

    Responsible for:

    - Initializing the database
    - Creating database tables
    - Verifying connectivity
    """

    def __init__(self) -> None:
        """Initialize the database manager."""

        self.engine = engine

        self.session_factory = SessionLocal

    def initialize(self) -> None:
        """
        Initialize the database.

        Creates all registered tables and verifies
        the database connection.
        """

        logger.info("Initializing SQLite database...")

        Base.metadata.create_all(bind=self.engine)

        self.verify_connection()

        logger.info("Database initialized successfully.")

    def verify_connection(self) -> None:
        """
        Verify database connectivity.

        Raises
        ------
        RuntimeError
            If a database connection cannot be established.
        """

        try:

            with self.engine.connect():

                logger.info(
                    "Database connection verified."
                )

        except Exception as exc:

            logger.exception(
                "Database connection failed."
            )

            raise RuntimeError(
                "Unable to establish database connection."
            ) from exc

    def get_session(self) -> Session:
        """
        Create a new database session.

        Returns
        -------
        Session
            SQLAlchemy database session.
        """

        return self.session_factory()

# ==============================================================================
# Session Dependency
# ==============================================================================


def get_db():
    """
    Yield a database session.

    This function is intended to be used as a FastAPI dependency.

    Example
    -------
        @router.get("/")
        def endpoint(db: Session = Depends(get_db)):
            ...
    """

    db = database_manager.get_session()

    try:
        yield db

    finally:
        db.close()


# ==============================================================================
# Singleton
# ==============================================================================

database_manager = DatabaseManager()

database_manager.initialize()


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "engine",
    "Base",
    "SessionLocal",
    "DatabaseManager",
    "database_manager",
    "get_db",
]