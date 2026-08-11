"""
Plugin Result Model for the AI Memory Forensic Investigation Assistant.

This module defines the PluginResult entity, representing parsed
artifacts generated from a Volatility plugin execution.

Author:
    FIA Development Team
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from app.database.database import Base

# ==============================================================================
# Plugin Result Model
# ==============================================================================


class PluginResult(Base):
    """
    Represents parsed forensic artifacts produced by a Volatility plugin.

    Each record belongs to a single plugin execution and stores the
    structured output generated after parsing the plugin results.
    """

    __tablename__ = "plugin_results"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    plugin_execution_id: Mapped[int] = mapped_column(
        ForeignKey("plugin_executions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    artifact_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    artifact_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    artifact_value: Mapped[str] = mapped_column(
        String(5000),
        nullable=False,
    )

    confidence_score: Mapped[int] = mapped_column(
        Integer,
        default=100,
        nullable=False,
    )

    risk_level: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
        index=True,
    )

    risk_reasons: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    risk_indicators: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    rule_version: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    # ==========================================================================
    # Relationships
    # ==========================================================================

    plugin_execution: Mapped["PluginExecution"] = relationship(
        "PluginExecution",
        back_populates="plugin_results",
    )

    # ==========================================================================
    # Object Representation
    # ==========================================================================

    def __repr__(self) -> str:
        """
        Return a readable representation of the PluginResult object.
        """

        return (
            f"PluginResult("
            f"id={self.id}, "
            f"artifact_type='{self.artifact_type}', "
            f"artifact_name='{self.artifact_name}'"
            f")"
        )

# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "PluginResult",
]
