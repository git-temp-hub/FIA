"""
Upload API

Receives memory dumps and registers them for forensic investigation.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.database import get_db
from app.database.repositories import CaseRepository, MemoryDumpRepository
from app.models.case import Case
from app.models.memory_dump import MemoryDump
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
    db: Session = Depends(get_db),
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

        case_repository = CaseRepository(db)
        memory_dump_repository = MemoryDumpRepository(db)

        case = Case(
            case_name=investigation_id,
            investigator="default",
            description=f"Memory dump investigation: {metadata.filename}",
        )

        case_repository.create(case)

        memory_dump_record = MemoryDump(
            case_id=case.id,
            investigation_id=investigation_id,
            filename=metadata.filename,
            original_path=str(metadata.original_path),
            stored_path=str(metadata.stored_path),
            sha256_hash=metadata.sha256,
            file_size=metadata.file_size,
            status="uploaded",
            progress=0,
        )

        memory_dump_repository.create(memory_dump_record)

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

    except HTTPException:
        raise

    except ValueError as exc:
        logger.warning(
            "Upload rejected for filename '%s': %s",
            file.filename,
            exc,
        )
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        logger.exception(
            "Upload failed for filename '%s'.",
            file.filename,
        )
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred during upload.",
        ) from exc

    finally:

        if temporary_path and temporary_path.exists():
            temporary_path.unlink(missing_ok=True)