"""
Investigation API
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter

from app.schemas.investigation import (
    InvestigationStartRequest,
    InvestigationStartResponse,
    InvestigationStatusResponse,
)

from app.services.investigation_service import (
    investigation_service,
)

router = APIRouter(
    prefix="/investigation",
    tags=["Investigation"],
)


DEFAULT_PLUGINS = [
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.cmdline",
    "windows.dlllist",
    "windows.handles",
    "windows.netscan",
    "windows.filescan",
    "windows.registry.printkey",
    "windows.malfind",
]


@router.post(
    "/start",
    response_model=InvestigationStartResponse,
)
async def start_investigation(
    request: InvestigationStartRequest,
):

    investigation_service.execute_plugins(
        memory_dump=Path(request.memory_dump_path),
        plugins=DEFAULT_PLUGINS,
    )

    return InvestigationStartResponse(
        investigation_id=request.investigation_id,
        status="completed",
        message="Investigation completed successfully.",
    )


@router.get(
    "/status/{investigation_id}",
    response_model=InvestigationStatusResponse,
)
async def investigation_status(
    investigation_id: str,
):

    return InvestigationStatusResponse(
        investigation_id=investigation_id,
        status="completed",
        progress=100,
    )