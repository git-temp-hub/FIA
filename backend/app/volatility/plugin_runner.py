"""
Volatility Plugin Runner for the AI Memory Forensic Investigation Assistant.

This module executes validated Volatility 3 plugins against
memory dump files and captures structured execution results.

Author:
    FIA Development Team
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from datetime import datetime
from typing import Final

from app.core.logging import get_logger
from app.volatility.manager import volatility_manager
from app.volatility.plugin_registry import plugin_registry

logger = get_logger(__name__)

# ==============================================================================
# Constants
# ==============================================================================

DEFAULT_EXECUTION_TIMEOUT: Final[int] = 1800  # 30 minutes

# ==============================================================================
# Plugin Execution Result
# ==============================================================================


@dataclass(slots=True)
class PluginExecutionResult:
    """
    Represents the result of executing a Volatility plugin.
    """

    plugin_name: str

    memory_dump: Path

    command: list[str]

    success: bool

    return_code: int

    started_at: datetime

    finished_at: datetime

    execution_time: float

    stdout: str

    stderr: str

    json_output: str | None

    error_message: str | None

# ==============================================================================
# Plugin Runner
# ==============================================================================


class PluginRunner:
    """
    Executes validated Volatility plugins against memory dumps.
    """

    def __init__(self) -> None:
        self._manager = volatility_manager
        self._registry = plugin_registry

        logger.info(
            "Plugin Runner initialized."
        )

    # --------------------------------------------------------------------------
    # Properties
    # --------------------------------------------------------------------------

    @property
    def manager(self):
        """
        Return the configured Volatility manager.
        """
        return self._manager

    @property
    def registry(self):
        """
        Return the plugin registry.
        """
        return self._registry

    # --------------------------------------------------------------------------
    # Command Builder
    # --------------------------------------------------------------------------

    def build_command(
        self,
        memory_dump: Path,
        plugin_name: str,
    ) -> list[str]:
        """
        Build the Volatility execution command.
        """

        self.registry.validate_plugin(plugin_name)

        return [
            str(self.manager.executable),
            "-f",
            str(memory_dump),
            "-r",
            "json",
            plugin_name,
        ]
    # --------------------------------------------------------------------------
    # Plugin Execution
    # --------------------------------------------------------------------------

    def execute_plugin(
        self,
        memory_dump: Path,
        plugin_name: str,
        timeout: int = DEFAULT_EXECUTION_TIMEOUT,
    ) -> PluginExecutionResult:
        """
        Execute a Volatility plugin and capture its output.
        """

        import subprocess

        command = self.build_command(
            memory_dump=memory_dump,
            plugin_name=plugin_name,
        )

        logger.info(
            "Executing plugin: %s",
            plugin_name,
        )

        started_at = datetime.now()

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            finished_at = datetime.now()

            execution_time = (
                finished_at - started_at
            ).total_seconds()

            success = process.returncode == 0

            logger.info(
                "Plugin '%s' finished in %.2f seconds.",
                plugin_name,
                execution_time,
            )

            return PluginExecutionResult(
                plugin_name=plugin_name,
                memory_dump=memory_dump,
                command=command,
                success=success,
                return_code=process.returncode,
                started_at=started_at,
                finished_at=finished_at,
                execution_time=execution_time,
                stdout=process.stdout,
                stderr=process.stderr,
                json_output=process.stdout if success else None,
                error_message=None if success else process.stderr,
            )

        except subprocess.TimeoutExpired:
            finished_at = datetime.now()

            logger.exception(
                "Plugin '%s' timed out.",
                plugin_name,
            )

            return PluginExecutionResult(
                plugin_name=plugin_name,
                memory_dump=memory_dump,
                command=command,
                success=False,
                return_code=-1,
                started_at=started_at,
                finished_at=finished_at,
                execution_time=(
                    finished_at - started_at
                ).total_seconds(),
                stdout="",
                stderr="Execution timed out.",
                json_output=None,
                error_message="Execution timed out.",
            )
# ==============================================================================
# Singleton Instance
# ==============================================================================

plugin_runner = PluginRunner()

# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "PluginExecutionResult",
    "PluginRunner",
    "plugin_runner",
]
