"""
Upload API

Receives memory dumps and automatically starts the forensic
investigation workflow.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.core.logging import get_logger
from app.services.investigation_service import investigation_service

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
    Upload a memory dump and start the investigation workflow.

    Workflow
    --------
    1. Save uploaded file temporarily.
    2. Validate and store memory dump.
    3. Execute the initial Volatility plugin.
    4. Return investigation metadata.
    """

    try:

        suffix = Path(file.filename).suffix

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=suffix,
        ) as temp_file:

            content = await file.read()

            temp_file.write(content)

            temporary_path = Path(temp_file.name)

        # ------------------------------------------------------------
        # Start complete investigation workflow
        # ------------------------------------------------------------

        result = investigation_service.process_memory_dump(
            temporary_path
        )

        metadata = result["memory_dump"]

        execution = result["execution"]

        # Remove temporary uploaded file
        temporary_path.unlink(missing_ok=True)

        logger.info(
            "Memory dump uploaded and investigation started successfully."
        )

        return {
            "status": "success",
            "message": "Memory dump uploaded successfully.",

            "memory_dump": {
                "filename": metadata.filename,
                "extension": metadata.extension,
                "size": metadata.file_size,
                "sha256": metadata.sha256,
                "stored_path": str(metadata.stored_path),
            },

            "plugin_execution": {
                "plugin": execution.plugin,
                "success": execution.success,
                "return_code": execution.return_code,
                "stdout_length": len(execution.stdout),
                "stderr_length": len(execution.stderr),
            },
        }

    except Exception as exc:

        logger.exception(
            "Upload failed."
        )

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )