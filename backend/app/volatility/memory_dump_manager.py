"""
Memory Dump Manager for the AI Memory Forensic Investigation Assistant.

This module provides secure handling of uploaded memory dump files,
including validation, hashing, metadata extraction, duplicate detection,
and storage management.

Author:
    FIA Development Team
"""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# ==============================================================================
# Constants
# ==============================================================================

SUPPORTED_MEMORY_EXTENSIONS: Final[tuple[str, ...]] = (
    ".raw",
    ".mem",
    ".bin",
    ".dmp",
    ".img",
)

DEFAULT_CHUNK_SIZE: Final[int] = 1024 * 1024  # 1 MB

MAX_MEMORY_DUMP_SIZE: Final[int] = 1024 * 1024 * 1024 * 64  # 64 GB


# ==============================================================================
# Memory Dump Information
# ==============================================================================


@dataclass(slots=True)
class MemoryDumpInfo:
    """
    Stores metadata describing a validated memory dump.
    """

    original_path: Path

    stored_path: Path

    filename: str

    extension: str

    file_size: int

    sha256: str

# ==============================================================================
# Memory Dump Manager
# ==============================================================================


class MemoryDumpManager:
    """
    Handles validation and storage of uploaded memory dump files.
    """

    def __init__(self) -> None:
        self._storage_directory = settings.storage.uploads

        self._storage_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        logger.info(
            "Memory dump storage initialized: %s",
            self._storage_directory,
        )

    # --------------------------------------------------------------------------
    # Properties
    # --------------------------------------------------------------------------

    @property
    def storage_directory(self) -> Path:
        """
        Return the configured upload directory.
        """
        return self._storage_directory

    # --------------------------------------------------------------------------
    # Validation
    # --------------------------------------------------------------------------

    def validate_memory_dump(
        self,
        file_path: Path,
    ) -> None:
        """
        Validate a memory dump before processing.

        Raises
        ------
        FileNotFoundError
            If the file does not exist.
        ValueError
            If the extension or size is invalid.
        """

        if not file_path.exists():
            raise FileNotFoundError(
                f"Memory dump not found: {file_path}"
            )

        if file_path.suffix.lower() not in SUPPORTED_MEMORY_EXTENSIONS:
            raise ValueError(
                f"Unsupported memory dump format: {file_path.suffix}"
            )

        file_size = file_path.stat().st_size

        if file_size == 0:
            raise ValueError(
                "Memory dump file is empty."
            )

        if file_size > MAX_MEMORY_DUMP_SIZE:
            raise ValueError(
                "Memory dump exceeds the maximum supported size."
            )

        logger.info(
            "Memory dump validation successful: %s",
            file_path.name,
        )

    # --------------------------------------------------------------------------
    # Hashing
    # --------------------------------------------------------------------------

    def calculate_sha256(
        self,
        file_path: Path,
    ) -> str:
        """
        Calculate the SHA-256 hash of a memory dump.

        Parameters
        ----------
        file_path : Path
            Path to the memory dump.

        Returns
        -------
        str
            SHA-256 hexadecimal digest.
        """

        sha256 = hashlib.sha256()

        with file_path.open("rb") as file:
            while chunk := file.read(DEFAULT_CHUNK_SIZE):
                sha256.update(chunk)

        digest = sha256.hexdigest()

        logger.info(
            "SHA-256 calculated for %s",
            file_path.name,
        )

        return digest

    # --------------------------------------------------------------------------
    # Metadata Extraction
    # --------------------------------------------------------------------------

    def extract_metadata(
        self,
        file_path: Path,
    ) -> MemoryDumpInfo:
        """
        Extract metadata from a validated memory dump.

        Parameters
        ----------
        file_path : Path
            Memory dump path.

        Returns
        -------
        MemoryDumpInfo
        """

        self.validate_memory_dump(file_path)

        return MemoryDumpInfo(
            original_path=file_path,
            stored_path=file_path,
            filename=file_path.name,
            extension=file_path.suffix.lower(),
            file_size=file_path.stat().st_size,
            sha256=self.calculate_sha256(file_path),
        )

    # --------------------------------------------------------------------------
    # Storage
    # --------------------------------------------------------------------------

    def store_memory_dump(
        self,
        file_path: Path,
    ) -> MemoryDumpInfo:
        """
        Validate and securely store a memory dump.

        Parameters
        ----------
        file_path : Path
            Original uploaded file.

        Returns
        -------
        MemoryDumpInfo
        """

        metadata = self.extract_metadata(file_path)

        destination = self.storage_directory / metadata.filename

        if not destination.exists():
            shutil.copy2(file_path, destination)

            logger.info(
                "Memory dump stored successfully: %s",
                destination,
            )
        else:
            logger.warning(
                "Memory dump already exists: %s",
                destination.name,
            )

        metadata.stored_path = destination

        return metadata

# ==============================================================================
# Singleton Instance
# ==============================================================================

memory_dump_manager = MemoryDumpManager()


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "MemoryDumpInfo",
    "MemoryDumpManager",
    "memory_dump_manager",
]
