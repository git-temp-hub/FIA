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
from sqlalchemy import inspect
from sqlalchemy import text
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
# Lightweight Migrations
# ==============================================================================


def ensure_chat_session_column(engine: Engine) -> None:
    """
    Backward-compatible schema migration for existing databases.

    Adds the nullable ``chat_messages.session_id`` column used to isolate
    conversation sessions inside an investigation. The column is only
    added when it is missing, so existing rows are never modified.
    """

    table_exists = inspect(engine).has_table("chat_messages")

    if not table_exists:
        return

    with engine.connect() as connection:
        columns = {
            row[1]
            for row in connection.execute(
                text("PRAGMA table_info(chat_messages)")
            )
        }

        if "session_id" not in columns:
            connection.execute(
                text(
                    "ALTER TABLE chat_messages "
                    "ADD COLUMN session_id VARCHAR(64)"
                )
            )
            connection.commit()
            logger.info("Added chat_messages.session_id column.")


def ensure_evidence_risk_columns(engine: Engine) -> None:
    """
    Backward-compatible schema migration for existing databases.

    Adds the nullable risk-classification columns to ``plugin_results``
    used by the evidence classifier. Columns are only added when missing,
    so existing rows are never modified.
    """

    table_exists = inspect(engine).has_table("plugin_results")

    if not table_exists:
        return

    additions = {
        "risk_level": "VARCHAR(20)",
        "risk_reasons": "TEXT",
        "risk_indicators": "TEXT",
        "rule_version": "VARCHAR(20)",
    }

    with engine.connect() as connection:
        columns = {
            row[1]
            for row in connection.execute(
                text("PRAGMA table_info(plugin_results)")
            )
        }

        for column_name, column_ddl in additions.items():

            if column_name not in columns:
                connection.execute(
                    text(
                        "ALTER TABLE plugin_results "
                        f"ADD COLUMN {column_name} {column_ddl}"
                    )
                )
                connection.commit()
                logger.info(
                    "Added plugin_results.%s column.",
                    column_name,
                )


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

        import app.models  # noqa: F401

        Base.metadata.create_all(bind=self.engine)

        ensure_chat_session_column(self.engine)

        ensure_evidence_risk_columns(self.engine)

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