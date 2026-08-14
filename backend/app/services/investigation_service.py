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

import asyncio
import time
from pathlib import Path
from typing import Any, Callable

from app.core.logging import get_logger
from app.volatility.execution_engine import ExecutionResult, execution_engine
from app.volatility.memory_dump_manager import (
    AsyncReadable,
    memory_dump_manager,
)

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

    async def prepare_memory_dump_stream(
        self,
        filename: str | None,
        stream: AsyncReadable,
    ):
        """
        Stream an uploaded memory dump into storage with bounded memory.

        Parameters
        ----------
        filename : the original upload filename.
        stream : an async reader (e.g. FastAPI ``UploadFile``).

        Returns
        -------
        MemoryDumpInfo
        """

        logger.info(
            "Streaming memory dump: %s",
            filename,
        )

        return await memory_dump_manager.stream_to_storage(
            filename=filename,
            stream=stream,
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
    # Investigation Run
    # ------------------------------------------------------------------

    def run_investigation(
        self,
        memory_dump: Path,
        plugins: list[str],
        on_plugin_started: Callable[[str], None] | None = None,
        on_plugin_completed: (
            Callable[[int, int, ExecutionResult, float], None] | None
        ) = None,
    ) -> list[ExecutionResult]:
        """
        Execute an investigation across the provided plugins.

        Individual plugin failures are captured in their ExecutionResult
        and never terminate the investigation.

        Parameters
        ----------
        memory_dump : Path

        plugins : list[str]

        on_plugin_started : Callable, optional
            Invoked with the plugin name before it runs.

        on_plugin_completed : Callable, optional
            Invoked after each plugin with
            (index, total, ExecutionResult, execution_time_seconds).

        Returns
        -------
        list[ExecutionResult]
        """

        logger.info(
            "Starting investigation on %s with %d plugins.",
            memory_dump,
            len(plugins),
        )

        results: list[ExecutionResult] = []

        total = len(plugins)

        for index, plugin_name in enumerate(plugins):

            if on_plugin_started is not None:
                on_plugin_started(plugin_name)

            started_at = time.monotonic()

            try:
                result = self.execute_plugin(
                    memory_dump=memory_dump,
                    plugin_name=plugin_name,
                )
            except Exception as exc:
                logger.exception(
                    "Plugin '%s' raised during execution.",
                    plugin_name,
                )
                result = ExecutionResult(
                    plugin=plugin_name,
                    success=False,
                    return_code=-1,
                    stdout="",
                    stderr=str(exc),
                    json_output=None,
                )

            execution_time = time.monotonic() - started_at

            results.append(result)

            if on_plugin_completed is not None:
                on_plugin_completed(
                    index,
                    total,
                    result,
                    execution_time,
                )

        logger.info(
            "Investigation on %s completed with %d plugin results.",
            memory_dump,
            len(results),
        )

        return results

    # ------------------------------------------------------------------
    # Parallel Investigation Run
    # ------------------------------------------------------------------

    async def run_investigation_async(
        self,
        memory_dump: Path,
        plugins: list[str],
        on_plugin_started: Callable[[str], None] | None = None,
        on_plugin_completed: (
            Callable[[int, int, ExecutionResult, float], None] | None
        ) = None,
        max_concurrency: int = 4,
    ) -> list[ExecutionResult]:
        """
        Execute an investigation across the provided plugins concurrently.

        Each plugin's blocking ``subprocess`` work runs on a thread via
        ``asyncio.to_thread`` (never on the event loop), limited to
        ``max_concurrency`` in-flight plugins. The callbacks are invoked on
        the event loop, so database persistence stays single-threaded and
        thread-safe. Callback ``index`` counts completed plugins, keeping
        progress monotonic regardless of completion order.

        Individual plugin failures are captured in their ExecutionResult
        and never terminate the investigation.

        Parameters
        ----------
        memory_dump : Path

        plugins : list[str]

        on_plugin_started : Callable, optional

        on_plugin_completed : Callable, optional

        max_concurrency : int, optional
            Maximum number of plugins executed simultaneously.

        Returns
        -------
        list[ExecutionResult]
            One result per plugin, in the same order as ``plugins``.
        """

        total = len(plugins)

        logger.info(
            "Starting parallel investigation on %s with %d plugins "
            "(max concurrency %d).",
            memory_dump,
            total,
            max_concurrency,
        )

        if total == 0:
            return []

        results: list[ExecutionResult | None] = [None] * total

        semaphore = asyncio.Semaphore(
            max(1, int(max_concurrency))
        )

        completed_counter = 0

        async def run_one(
            plugin_name: str,
            position: int,
        ) -> None:
            nonlocal completed_counter

            async with semaphore:

                if on_plugin_started is not None:
                    on_plugin_started(plugin_name)

                started_at = time.monotonic()

                try:
                    result = await asyncio.to_thread(
                        self.execute_plugin,
                        memory_dump=memory_dump,
                        plugin_name=plugin_name,
                    )
                except Exception as exc:
                    logger.exception(
                        "Plugin '%s' raised during parallel execution.",
                        plugin_name,
                    )
                    result = ExecutionResult(
                        plugin=plugin_name,
                        success=False,
                        return_code=-1,
                        stdout="",
                        stderr=str(exc),
                        json_output=None,
                    )

                execution_time = time.monotonic() - started_at

                results[position] = result

                index = completed_counter
                completed_counter += 1

                if on_plugin_completed is not None:
                    on_plugin_completed(
                        index,
                        total,
                        result,
                        execution_time,
                    )

        await asyncio.gather(
            *(
                run_one(plugin_name, position)
                for position, plugin_name in enumerate(plugins)
            )
        )

        logger.info(
            "Parallel investigation on %s completed with %d plugin results.",
            memory_dump,
            len(results),
        )

        return [result for result in results if result is not None]

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