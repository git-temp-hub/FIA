"""
Investigation API
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.database import get_db
from app.database.repositories import (
    CaseRepository,
    MemoryDumpRepository,
    PluginExecutionRepository,
    PluginResultRepository,
)
from app.models.case import Case
from app.models.memory_dump import MemoryDump
from app.models.plugin_execution import PluginExecution
from app.models.plugin_result import PluginResult
from app.parsers.evidence_normalizer import evidence_normalizer
from app.parsers.volatility_json_parser import volatility_json_parser
from app.schemas.investigation import (
    InvestigationStartRequest,
    InvestigationStartResponse,
    InvestigationStatusResponse,
)

from app.services.investigation_service import (
    investigation_service,
)

from app.services.risk_classification_service import (
    classify_investigation_evidence,
)

logger = get_logger(__name__)

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
    db: Session = Depends(get_db),
):

    memory_dump_repository = MemoryDumpRepository(db)
    case_repository = CaseRepository(db)
    plugin_execution_repository = PluginExecutionRepository(db)
    plugin_result_repository = PluginResultRepository(db)

    memory_dump_record = memory_dump_repository.get_by_investigation_id(
        request.investigation_id
    )

    if memory_dump_record is None:

        metadata = investigation_service.prepare_memory_dump(
            Path(request.memory_dump_path),
        )

        case = Case(
            case_name=request.investigation_id,
            investigator="default",
            description=(
                f"Memory dump investigation: {metadata.filename}"
            ),
        )

        case_repository.create(case)

        memory_dump_record = MemoryDump(
            case_id=case.id,
            investigation_id=request.investigation_id,
            filename=metadata.filename,
            original_path=str(metadata.original_path),
            stored_path=str(metadata.stored_path),
            sha256_hash=metadata.sha256,
            file_size=metadata.file_size,
            status="running",
            progress=0,
        )

        memory_dump_repository.create(memory_dump_record)

    else:

        memory_dump_record.status = "running"
        memory_dump_record.progress = 0

        memory_dump_repository.update(memory_dump_record)

    memory_dump_path = Path(memory_dump_record.stored_path)

    executions: dict[str, PluginExecution] = {}

    def on_plugin_started(plugin_name: str) -> None:

        execution = PluginExecution(
            memory_dump_id=memory_dump_record.id,
            plugin_name=plugin_name,
            execution_status="running",
        )

        plugin_execution_repository.create(execution)

        executions[plugin_name] = execution

    def on_plugin_completed(
        index: int,
        total: int,
        result,
        execution_time: float,
    ) -> None:

        execution = executions.get(result.plugin)

        if execution is not None:

            execution.execution_status = (
                "completed" if result.success else "failed"
            )
            execution.execution_time = execution_time
            execution.error_message = result.stderr or None

            plugin_execution_repository.update(execution)

            if result.success and result.json_output:

                try:

                    parsed = volatility_json_parser.parse(
                        result.plugin,
                        result.json_output,
                    )

                    records = evidence_normalizer.normalize(
                        result.plugin,
                        parsed.rows,
                    )

                    for evidence in records:

                        plugin_result_repository.create(
                            PluginResult(
                                plugin_execution_id=execution.id,
                                artifact_type=evidence.artifact_type,
                                artifact_name=result.plugin,
                                artifact_value=json.dumps(
                                    evidence.attributes,
                                    default=str,
                                )[:5000],
                            )
                        )

                except Exception as exc:

                    logger.warning(
                        "Failed to parse results for plugin '%s': %s",
                        result.plugin,
                        exc,
                    )

        else:

            logger.error(
                "No execution record found for plugin '%s'.",
                result.plugin,
            )

        memory_dump_record.progress = int(
            (index + 1) / total * 100
        )

        memory_dump_repository.update(memory_dump_record)

    try:

        investigation_service.run_investigation(
            memory_dump=memory_dump_path,
            plugins=DEFAULT_PLUGINS,
            on_plugin_started=on_plugin_started,
            on_plugin_completed=on_plugin_completed,
        )

    except Exception as exc:

        logger.exception("Investigation failed.")

        memory_dump_record.status = "failed"

        memory_dump_repository.update(memory_dump_record)

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )

    memory_dump_record.status = "completed"
    memory_dump_record.progress = 100

    memory_dump_repository.update(memory_dump_record)

    try:

        classify_investigation_evidence(
            db,
            request.investigation_id,
        )

    except Exception as exc:

        logger.warning(
            "Risk classification failed for investigation '%s': %s",
            request.investigation_id,
            exc,
        )

    try:

        from app.services.rag.indexing_service import (
            rag_indexing_service,
        )

        rag_indexing_service.index_investigation(
            request.investigation_id,
            db,
        )

    except Exception as exc:

        logger.warning(
            "RAG indexing failed for investigation '%s': %s",
            request.investigation_id,
            exc,
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
    db: Session = Depends(get_db),
):

    memory_dump_repository = MemoryDumpRepository(db)

    record = memory_dump_repository.get_by_investigation_id(
        investigation_id
    )

    if record is None:

        return InvestigationStatusResponse(
            investigation_id=investigation_id,
            status="not_found",
            progress=0,
        )

    return InvestigationStatusResponse(
        investigation_id=investigation_id,
        status=record.status,
        progress=record.progress,
    )
