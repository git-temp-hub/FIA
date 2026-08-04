"""
Upload API

Receives memory dumps and registers them for forensic investigation.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.core.logging import get_logger
from app.services.investigation_service import investigation_service
from app.utils.investigation_id import generate_investigation_id

logger = get_logger(__name__)

router = APIRouter(
    prefix="/upload",
    tags=["Upload"],
)


@router.post("/")
async def upload_memory_dump(
    file: UploadFile = File(...),
):
    """
    Upload a memory dump and create a new investigation.
    """

    temporary_path: Path | None = None

    try:

        investigation_id = generate_investigation_id()

        suffix = Path(file.filename).suffix

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=suffix,
        ) as temp_file:

            content = await file.read()

            temp_file.write(content)

            temporary_path = Path(temp_file.name)

        metadata = investigation_service.prepare_memory_dump(
            temporary_path,
        )

        logger.info(
            "Investigation created: %s",
            investigation_id,
        )

        return {
            "status": "success",
            "investigation_id": investigation_id,
            "filename": metadata.filename,
            "size": metadata.file_size,
            "sha256": metadata.sha256,
            "stored_path": str(metadata.stored_path),
        }

    except Exception as exc:

        logger.exception("Upload failed.")

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    finally:

        if temporary_path and temporary_path.exists():
            temporary_path.unlink(missing_ok=True)