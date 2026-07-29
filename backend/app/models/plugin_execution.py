"""
Plugin Execution Model for the AI Memory Forensic Investigation Assistant.

This module defines the PluginExecution entity, representing a single
Volatility plugin execution performed on a memory dump.

Author:
    FIA Development Team
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from app.database.database import Base

# ==============================================================================
# Plugin Execution Model
# ==============================================================================


class PluginExecution(Base):
    """
    Represents a single execution of a Volatility plugin.

    Each execution belongs to one memory dump and stores metadata about
    the execution status, timing, and generated output.
    """

    __tablename__ = "plugin_executions"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    memory_dump_id: Mapped[int] = mapped_column(
        ForeignKey("memory_dumps.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    plugin_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    execution_status: Mapped[str] = mapped_column(
        String(50),
        default="pending",
        nullable=False,
    )

    execution_time: Mapped[float | None] = mapped_column(
        nullable=True,
    )

    output_file: Mapped[str | None] = mapped_column(
        String(1024),
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        String(2000),
        nullable=True,
    )

    executed_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    # ==========================================================================
    # Relationships
    # ==========================================================================

    memory_dump: Mapped["MemoryDump"] = relationship(
        "MemoryDump",
        back_populates="plugin_executions",
    )

    plugin_results: Mapped[list["PluginResult"]] = relationship(
        "PluginResult",
        back_populates="plugin_execution",
        cascade="all, delete-orphan",
    )

    # ==========================================================================
    # Object Representation
    # ==========================================================================

    def __repr__(self) -> str:
        """
        Return a readable representation of the PluginExecution object.
        """

        return (
            f"PluginExecution("
            f"id={self.id}, "
            f"plugin_name='{self.plugin_name}', "
            f"status='{self.execution_status}'"
            f")"
        )

# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "PluginExecution",
]