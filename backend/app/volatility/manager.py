"""
Volatility Manager for the AI Memory Forensic Investigation Assistant.

This module provides a centralized interface for executing Volatility 3
plugins, validating the installation, managing subprocess execution,
capturing outputs, and returning structured execution results.

Author:
    FIA Development Team
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# ==============================================================================
# Constants
# ==============================================================================

VOLATILITY_EXECUTABLE: Final[str] = "vol"

DEFAULT_TIMEOUT: Final[int] = 300

SUPPORTED_OUTPUT_FORMATS: Final[tuple[str, ...]] = (
    "json",
    "text",
)

DEFAULT_OUTPUT_FORMAT: Final[str] = "json"


# ==============================================================================
# Execution Result
# ==============================================================================


@dataclass(slots=True)
class PluginExecutionResult:
    """
    Represents the result of a single Volatility plugin execution.
    """

    success: bool

    plugin_name: str

    command: list[str]

    return_code: int

    stdout: str

    stderr: str

    execution_time: float

    output_file: Path | None = None

# ==============================================================================
# Volatility Manager
# ==============================================================================


class VolatilityManager:
    """
    Central interface for interacting with Volatility 3.

    Responsibilities:
        - Verify installation
        - Execute plugins
        - Manage execution timeout
        - Capture stdout/stderr
        - Return structured execution results
    """

    def __init__(self) -> None:
        self._volatility_path = self._locate_volatility()

        logger.info(
            "Volatility executable detected: %s",
            self._volatility_path,
        )

    # --------------------------------------------------------------------------
    # Properties
    # --------------------------------------------------------------------------

    @property
    def executable(self) -> str:
        """
        Return the detected Volatility executable.
        """
        return self._volatility_path

    @property
    def is_available(self) -> bool:
        """
        Return True if Volatility is available.
        """
        return bool(self._volatility_path)

    # --------------------------------------------------------------------------
    # Installation Detection
    # --------------------------------------------------------------------------

    def _locate_volatility(self) -> str:
        """
        Locate the Volatility executable.

        Returns
        -------
        str
            Absolute executable path.

        Raises
        ------
        RuntimeError
            If Volatility cannot be found.
        """

        executable = shutil.which(VOLATILITY_EXECUTABLE)

        if executable:
            return executable

        raise RuntimeError(
            "Volatility 3 executable not found. "
            "Ensure 'vol' is installed and available in PATH."
        )

    # --------------------------------------------------------------------------
    # Plugin Execution
    # --------------------------------------------------------------------------

    def execute_plugin(
        self,
        memory_dump: Path,
        plugin_name: str,
        output_file: Path | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> PluginExecutionResult:
        """
        Execute a Volatility plugin against a memory dump.

        Parameters
        ----------
        memory_dump : Path
            Path to the memory dump.
        plugin_name : str
            Volatility plugin name.
        output_file : Path | None
            Optional output file.
        timeout : int
            Maximum execution time in seconds.

        Returns
        -------
        PluginExecutionResult
        """

        command: list[str] = [
            self.executable,
            "-f",
            str(memory_dump),
            plugin_name,
            "--output",
            DEFAULT_OUTPUT_FORMAT,
        ]

        if output_file is not None:
            command.extend(
                [
                    "--output-file",
                    str(output_file),
                ]
            )

        logger.info(
            "Executing Volatility plugin: %s",
            plugin_name,
        )

        try:
            completed_process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )

            execution_result = PluginExecutionResult(
                success=completed_process.returncode == 0,
                plugin_name=plugin_name,
                command=command,
                return_code=completed_process.returncode,
                stdout=completed_process.stdout,
                stderr=completed_process.stderr,
                execution_time=0.0,
                output_file=output_file,
            )

            if execution_result.success:
                logger.info(
                    "Plugin '%s' executed successfully.",
                    plugin_name,
                )
            else:
                logger.error(
                    "Plugin '%s' failed with exit code %s.",
                    plugin_name,
                    completed_process.returncode,
                )

            return execution_result

        except subprocess.TimeoutExpired as exc:
            logger.exception(
                "Plugin '%s' timed out.",
                plugin_name,
            )

            return PluginExecutionResult(
                success=False,
                plugin_name=plugin_name,
                command=command,
                return_code=-1,
                stdout=exc.stdout or "",
                stderr="Execution timed out.",
                execution_time=float(timeout),
                output_file=output_file,
            )

    # --------------------------------------------------------------------------
    # Utility Methods
    # --------------------------------------------------------------------------

    def verify_installation(self) -> bool:
        """
        Verify that Volatility can be executed successfully.

        Returns
        -------
        bool
            True if Volatility responds successfully.
        """

        try:
            subprocess.run(
                [self.executable, "--help"],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )

            logger.info("Volatility installation verified successfully.")

            return True

        except Exception:
            logger.exception("Volatility installation verification failed.")

            return False


# ==============================================================================
# Singleton Instance
# ==============================================================================

volatility_manager = VolatilityManager()


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "PluginExecutionResult",
    "VolatilityManager",
    "volatility_manager",
]