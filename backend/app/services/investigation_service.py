"""
Investigation Service

Coordinates the complete forensic investigation workflow.

Responsibilities
----------------
1. Validate uploaded memory dump.
2. Securely store the memory dump.
3. Execute Volatility plugins.
4. (Future) Parse plugin outputs.
5. (Future) Normalize forensic artifacts.
6. (Future) Generate embeddings.
7. (Future) Store evidence in ChromaDB.
8. (Future) Record investigation metadata.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.core.logging import get_logger
from app.volatility.execution_engine import execution_engine
from app.volatility.memory_dump_manager import memory_dump_manager

logger = get_logger(__name__)


class InvestigationService:
    """
    High-level orchestration service.

    This class coordinates the complete forensic investigation
    workflow for the FIA backend.
    """

    def __init__(self) -> None:

        logger.info(
            "Investigation Service initialized."
        )

    # ------------------------------------------------------------------
    # Memory Dump Preparation
    # ------------------------------------------------------------------

    def prepare_memory_dump(
        self,
        memory_dump: Path,
    ):
        """
        Validate and securely store a memory dump.

        Parameters
        ----------
        memory_dump : Path

        Returns
        -------
        MemoryDumpInfo
        """

        logger.info(
            "Preparing memory dump: %s",
            memory_dump,
        )

        return memory_dump_manager.store_memory_dump(
            memory_dump
        )

    # ------------------------------------------------------------------
    # Plugin Execution
    # ------------------------------------------------------------------

    def execute_plugin(
        self,
        memory_dump: Path,
        plugin_name: str,
    ):
        """
        Execute a single Volatility plugin.

        Parameters
        ----------
        memory_dump : Path

        plugin_name : str

        Returns
        -------
        ExecutionResult
        """

        logger.info(
            "Executing plugin: %s",
            plugin_name,
        )

        return execution_engine.execute(
            memory_dump=memory_dump,
            plugin_name=plugin_name,
        )

    # ------------------------------------------------------------------
    # Batch Execution
    # ------------------------------------------------------------------

    def execute_plugins(
        self,
        memory_dump: Path,
        plugins: list[str],
    ):
        """
        Execute multiple Volatility plugins.

        Parameters
        ----------
        memory_dump : Path

        plugins : list[str]

        Returns
        -------
        list[ExecutionResult]
        """

        logger.info(
            "Executing %d plugins.",
            len(plugins),
        )

        return execution_engine.execute_multiple(
            memory_dump=memory_dump,
            plugins=plugins,
        )

    # ------------------------------------------------------------------
    # Complete Investigation Workflow
    # ------------------------------------------------------------------

    def process_memory_dump(
        self,
        memory_dump: Path,
    ) -> dict[str, Any]:
        """
        Execute the complete MVP investigation workflow.

        Workflow
        --------
        1. Validate memory dump.
        2. Store memory dump.
        3. Execute the initial Volatility plugin.
        4. Return investigation results.

        Parameters
        ----------
        memory_dump : Path

        Returns
        -------
        dict
        """

        logger.info(
            "Starting investigation workflow."
        )

        metadata = self.prepare_memory_dump(
            memory_dump
        )

        execution = self.execute_plugin(
            memory_dump=metadata.stored_path,
            plugin_name="windows.info",
        )

        logger.info(
            "Investigation workflow completed."
        )

        return {
            "memory_dump": metadata,
            "execution": execution,
        }


# ==============================================================================
# Singleton Instance
# ==============================================================================

investigation_service = InvestigationService()


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "InvestigationService",
    "investigation_service",
]