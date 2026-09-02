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
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

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


def max_memory_dump_size() -> int:
    """
    Return the currently configured maximum dump size, in bytes.

    Read from configuration on every call (rather than captured in a module
    constant) so a change saved from the Settings page takes effect without
    restarting the server.
    """

    return settings.upload.max_dump_size_bytes


# ==============================================================================
# Memory Dump Information
# ==============================================================================


class AsyncReadable(Protocol):
    """
    Minimal async read interface accepted by :meth:`MemoryDumpManager.stream_to_storage`.

    FastAPI's ``UploadFile`` satisfies this protocol, so the manager can
    stream uploads without depending on FastAPI types.
    """

    async def read(self, size: int = -1) -> bytes:
        """Return up to ``size`` bytes, or ``b''`` at end of stream."""


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

        if file_size > max_memory_dump_size():
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

    # --------------------------------------------------------------------------
    # Streaming Storage
    # --------------------------------------------------------------------------

    async def stream_to_storage(
        self,
        filename: str | None,
        stream: AsyncReadable,
    ) -> MemoryDumpInfo:
        """
        Stream an uploaded memory dump into storage with bounded memory.

        Reads ``stream`` in fixed-size chunks (never the full file at once),
        validating the extension up front and computing the SHA-256 and byte
        count incrementally while the limits are enforced. The completed file
        is moved into the storage directory; duplicate filenames are not
        overwritten, mirroring :meth:`store_memory_dump`.

        Parameters
        ----------
        filename : the original upload filename (basename is used).
        stream : an async reader (e.g. FastAPI ``UploadFile``).

        Returns
        -------
        MemoryDumpInfo describing the stored dump.

        Raises
        ------
        ValueError
            If the extension is unsupported, the stream is empty, or the
            content exceeds the configured maximum dump size.
        """

        size_limit = max_memory_dump_size()

        basename = Path(filename or "").name

        extension = Path(basename).suffix.lower()

        if extension not in SUPPORTED_MEMORY_EXTENSIONS:
            raise ValueError(
                f"Unsupported memory dump format: {extension}"
            )

        destination = self._storage_directory / basename

        sha256 = hashlib.sha256()

        total = 0

        temporary_path: Path | None = None

        source_path: Path | None = None

        try:

            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=extension,
            ) as temp_file:

                temporary_path = Path(temp_file.name)

                source_path = temporary_path

                while chunk := await stream.read(DEFAULT_CHUNK_SIZE):

                    total += len(chunk)

                    if total > size_limit:

                        raise ValueError(
                            "Memory dump exceeds the maximum supported size."
                        )

                    sha256.update(chunk)

                    temp_file.write(chunk)

            if total == 0:

                raise ValueError(
                    "Memory dump file is empty."
                )

            if not destination.exists():

                shutil.move(temporary_path, destination)

                temporary_path = None

                logger.info(
                    "Memory dump stored successfully: %s",
                    destination,
                )

            else:

                logger.warning(
                    "Memory dump already exists: %s",
                    destination.name,
                )

            return MemoryDumpInfo(
                original_path=source_path or destination,
                stored_path=destination,
                filename=basename,
                extension=extension,
                file_size=total,
                sha256=sha256.hexdigest(),
            )

        finally:

            if temporary_path is not None:

                temporary_path.unlink(missing_ok=True)

# ==============================================================================
# Singleton Instance
# ==============================================================================

memory_dump_manager = MemoryDumpManager()


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "AsyncReadable",
    "MemoryDumpInfo",
    "MemoryDumpManager",
    "max_memory_dump_size",
    "memory_dump_manager",
]
