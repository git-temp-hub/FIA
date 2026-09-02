"""
Volatility Plugin Runner for the AI Memory Forensic Investigation Assistant.

This module executes validated Volatility 3 plugins against
memory dump files and captures structured execution results.

Plugin stdout/stderr are streamed to temporary files on disk instead of
being buffered in RAM, so plugins that emit hundreds of megabytes of JSON
(customary for multi-gigabyte memory dumps) never exceed a bounded memory
footprint during execution. Successful JSON output is exposed as
``json_output_path`` and consumed (parsed) from disk by the caller, which
is then responsible for unlinking it.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger
from app.volatility.manager import volatility_manager
from app.volatility.plugin_registry import plugin_registry

logger = get_logger(__name__)

# ==============================================================================
# Constants
# ==============================================================================

def default_execution_timeout() -> int:
    """
    Return the configured per-plugin execution timeout, in seconds.

    Read from configuration on every call (rather than captured in a module
    constant) so a change saved from the Settings page applies to the next
    plugin execution without restarting the server.
    """

    return settings.analysis.plugin_timeout_seconds

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

    json_output_path: Path | None = None

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
        self._temp_directory = settings.storage.temp

        self._temp_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

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
        timeout: int | None = None,
    ) -> PluginExecutionResult:
        """
        Execute a Volatility plugin, streaming its output to disk.

        The subprocess writes stdout/stderr directly into temporary files so
        multi-hundred-MB JSON output is never held in RAM while Volatility
        runs. On success the JSON remains on disk (``json_output_path``);
        on failure the temporary files are removed and the error message is
        read from the captured stderr file.

        ``timeout`` defaults to the configured per-plugin timeout when not
        supplied explicitly.
        """

        if timeout is None:
            timeout = default_execution_timeout()

        command = self.build_command(
            memory_dump=memory_dump,
            plugin_name=plugin_name,
        )

        logger.info(
            "Executing plugin: %s",
            plugin_name,
        )

        started_at = datetime.now()

        stdout_path: Path | None = None
        stderr_path: Path | None = None

        try:

            with (
                tempfile.NamedTemporaryFile(
                    "wb",
                    delete=False,
                    prefix=f"{plugin_name}-",
                    suffix=".out",
                    dir=self._temp_directory,
                ) as stdout_file,
                tempfile.NamedTemporaryFile(
                    "wb",
                    delete=False,
                    prefix=f"{plugin_name}-",
                    suffix=".err",
                    dir=self._temp_directory,
                ) as stderr_file,
            ):

                stdout_path = Path(stdout_file.name)
                stderr_path = Path(stderr_file.name)

                process = subprocess.Popen(
                    command,
                    stdout=stdout_file,
                    stderr=stderr_file,
                )

                timed_out = False

                try:
                    process.wait(timeout=timeout)

                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    timed_out = True

                return_code = process.returncode

                finished_at = datetime.now()

                execution_time = (
                    finished_at - started_at
                ).total_seconds()

            # Both temp files are closed here, so they can be unlinked.

            if timed_out:

                stderr_text = self._read_output_text(stderr_path)

                self._cleanup_only(stderr_path)
                self._cleanup_only(stdout_path)

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
                    execution_time=execution_time,
                    stdout="",
                    stderr=stderr_text,
                    json_output=None,
                    error_message="Execution timed out.",
                )

            logger.info(
                "Plugin '%s' finished in %.2f seconds.",
                plugin_name,
                execution_time,
            )

            if return_code == 0:

                self._cleanup_only(stderr_path)

                return PluginExecutionResult(
                    plugin_name=plugin_name,
                    memory_dump=memory_dump,
                    command=command,
                    success=True,
                    return_code=return_code,
                    started_at=started_at,
                    finished_at=finished_at,
                    execution_time=execution_time,
                    stdout="",
                    stderr="",
                    json_output=None,
                    json_output_path=stdout_path,
                    error_message=None,
                )

            stderr_text = self._read_output_text(stderr_path)

            self._cleanup_only(stderr_path)
            self._cleanup_only(stdout_path)

            return PluginExecutionResult(
                plugin_name=plugin_name,
                memory_dump=memory_dump,
                command=command,
                success=False,
                return_code=return_code,
                started_at=started_at,
                finished_at=finished_at,
                execution_time=execution_time,
                stdout="",
                stderr=stderr_text,
                json_output=None,
                error_message=stderr_text,
            )

        except Exception as exc:
            logger.exception(
                "Plugin '%s' execution failed.",
                plugin_name,
            )

            self._cleanup_only(stderr_path)
            self._cleanup_only(stdout_path)

            finished_at = datetime.now()

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
                stderr=str(exc),
                json_output=None,
                error_message=str(exc),
            )

    # --------------------------------------------------------------------------
    # Helpers
    # --------------------------------------------------------------------------

    @staticmethod
    def _read_output_text(
        path: Path | None,
        limit: int = 100_000,
    ) -> str:
        """Read back at most ``limit`` chars of a streamed temp output."""

        if path is None or not path.exists():
            return ""

        try:
            text = path.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            return ""

        if len(text) > limit:
            text = text[:limit]

        return text

    @staticmethod
    def _cleanup_only(path: Path | None) -> None:
        """Remove a temp output file, ignoring errors."""

        if path is not None:
            path.unlink(missing_ok=True)

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
    "default_execution_timeout",
    "plugin_runner",
]