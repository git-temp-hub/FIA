"""
Centralized Logging Manager for the AI Memory Forensic Investigation Assistant.

This module initializes the application's logging system using the
configuration defined in:

    backend/configs/logging.yaml

Every FIA module should obtain loggers only through:

    from app.core.logging import get_logger

Author:
    FIA Development Team
"""

from __future__ import annotations

import logging
import logging.config
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.core.config import settings

# ==============================================================================
# Logging Configuration Loader
# ==============================================================================


def load_logging_configuration() -> dict[str, Any]:
    """
    Load the logging configuration from YAML.

    Returns:
        Parsed logging configuration dictionary.

    Raises:
        RuntimeError:
            If the logging configuration file cannot be found.

        RuntimeError:
            If the YAML file cannot be parsed.
    """

    config_path = settings.logging.config_path

    if not config_path.exists():
        raise RuntimeError(
            "Logging configuration file not found:\n"
            f"{config_path}"
        )

    try:
        with config_path.open(
            "r",
            encoding="utf-8",
        ) as file:

            configuration = yaml.safe_load(file)

    except yaml.YAMLError as exc:
        raise RuntimeError(
            "Failed to parse logging configuration:\n"
            f"{config_path}"
        ) from exc

    if not configuration:
        raise RuntimeError(
            "Logging configuration file is empty."
        )

    return configuration


# ==============================================================================
# Log Directory Management
# ==============================================================================


def ensure_log_directory(configuration: dict[str, Any]) -> None:
    """
    Ensure that the log file directory exists before
    logging is initialized.
    """

    handlers = configuration.get("handlers", {})

    file_handler = handlers.get("file")

    if not file_handler:
        return

    filename = file_handler.get("filename")

    if not filename:
        return

    log_file = Path(filename)

    if not log_file.is_absolute():
        log_file = Path.cwd() / log_file

    log_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    file_handler["filename"] = str(log_file.resolve())

    # ==============================================================================
# Logging Initialization
# ==============================================================================


@lru_cache(maxsize=1)
def initialize_logging() -> None:
    """
    Initialize the FIA logging system.

    This function is executed only once during the application's
    lifetime. Subsequent calls return immediately.
    """

    configuration = load_logging_configuration()

    ensure_log_directory(configuration)

    logging.config.dictConfig(configuration)

    logging.getLogger(__name__).info(
        "Logging system initialized successfully."
    )


# ==============================================================================
# Logger Factory
# ==============================================================================


def get_logger(name: str) -> logging.Logger:
    """
    Return a configured logger instance.

    Parameters
    ----------
    name:
        Usually __name__ of the calling module.

    Returns
    -------
    logging.Logger
        Configured logger.
    """

    initialize_logging()

    return logging.getLogger(name)

# ==============================================================================
# Startup Validation
# ==============================================================================


def verify_logging() -> None:
    """
    Verify that the logging system is operational.

    Raises
    ------
    RuntimeError
        If the logging system cannot create a logger.
    """

    logger = logging.getLogger("fia.startup")

    if logger is None:
        raise RuntimeError(
            "Failed to initialize the logging system."
        )


# ==============================================================================
# Public Initialization
# ==============================================================================

initialize_logging()

verify_logging()


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "get_logger",
    "initialize_logging",
]
