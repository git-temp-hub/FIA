"""
Volatility Execution Engine for the AI Memory Forensic Investigation Assistant.

This module coordinates the complete execution workflow for
Volatility plugins.

Responsibilities
----------------
1. Validate plugin requests.
2. Execute Volatility plugins.
3. Capture execution results.
4. Return structured execution data.

Author:
    FIA Development Team
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.core.logging import get_logger
from app.volatility.plugin_registry import plugin_registry
from app.volatility.plugin_runner import plugin_runner

logger = get_logger(__name__)


# ==============================================================================
# Execution Result
# ==============================================================================


@dataclass(slots=True)
class ExecutionResult:
    """
    Represents the result of a Volatility plugin execution.
    """

    plugin: str

    success: bool

    return_code: int

    stdout: str

    stderr: str

    json_output: Any | None = None


# ==============================================================================
# Volatility Execution Engine
# ==============================================================================


class VolatilityExecutionEngine:
    """
    Coordinates Volatility plugin execution.
    """

    def __init__(self) -> None:
        self.runner = plugin_runner

        self.registry = plugin_registry

        logger.info(
            "Volatility Execution Engine initialized."
        )
    # --------------------------------------------------------------------------
    # Plugin Validation
    # --------------------------------------------------------------------------

    def validate_plugin(
        self,
        plugin_name: str,
    ) -> None:
        """
        Validate a requested plugin.
        """

        self.registry.validate_plugin(plugin_name)

    # --------------------------------------------------------------------------
    # Plugin Execution
    # --------------------------------------------------------------------------

    def execute(
        self,
        memory_dump: Path,
        plugin_name: str,
    ) -> ExecutionResult:
        """
        Execute a Volatility plugin.
        """

        self.validate_plugin(plugin_name)

        result = self.runner.execute_plugin(
            memory_dump=memory_dump,
            plugin_name=plugin_name,
        )

        return ExecutionResult(
            plugin=plugin_name,
            success=result.success,
            return_code=result.return_code,
            stdout=result.stdout,
            stderr=result.stderr,
            json_output=result.json_output,
        )
    # --------------------------------------------------------------------------
    # Batch Execution
    # --------------------------------------------------------------------------

    def execute_multiple(
        self,
        memory_dump: Path,
        plugins: list[str],
    ) -> list[ExecutionResult]:
        """
        Execute multiple Volatility plugins sequentially.
        """

        results: list[ExecutionResult] = []

        logger.info(
            "Executing %d plugins.",
            len(plugins),
        )

        for plugin in plugins:
            try:
                result = self.execute(
                    memory_dump=memory_dump,
                    plugin_name=plugin,
                )

                results.append(result)

            except Exception as exc:
                logger.exception(
                    "Plugin execution failed: %s",
                    plugin,
                )

                results.append(
                    ExecutionResult(
                        plugin=plugin,
                        success=False,
                        return_code=-1,
                        stdout="",
                        stderr=str(exc),
                        json_output=None,
                    )
                )

        logger.info(
            "Completed execution of %d plugins.",
            len(results),
        )

        return results
# ==============================================================================
# Singleton Instance
# ==============================================================================

execution_engine = VolatilityExecutionEngine()

# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "ExecutionResult",
    "VolatilityExecutionEngine",
    "execution_engine",
]
