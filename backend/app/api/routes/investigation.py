"""
Investigation API
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.database.database import SessionLocal
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

from app.services.risk_classification_service import (
    classify_investigation_evidence,
)

from app.services.investigation_phase_tracker import (
    PHASE_CLASSIFYING,
    PHASE_COMPLETED,
    PHASE_INDEXING,
    PHASE_VOLATILITY,
    investigation_phase_tracker,
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


def compute_progress(
    completed_plugins: int,
    total_plugins: int,
) -> int:
    """
    Compute the investigation progress percentage.

    Progress reflects the number of plugins that have actually completed,
    never elapsed time. 0/10 = 0%, 1/10 = 10%, ..., 10/10 = 100%.

    Parameters
    ----------
    completed_plugins : int
        Number of plugins that have finished.

    total_plugins : int
        Total number of plugins scheduled.

    Returns
    -------
    int
        Progress percentage clamped to [0, 100].
    """

    if total_plugins <= 0:
        return 0

    return min(100, int(completed_plugins / total_plugins * 100))


def _run_evidence_indexing(
    investigation_id: str,
    session_factory=SessionLocal,
) -> None:
    """
    Index an investigation's evidence into the vector store.

    Runs on the request's background tasks with a fresh database session
    so a slow or failing indexing pass never blocks the investigation
    response. Failures are logged and swallowed on purpose.
    """

    investigation_phase_tracker.set(
        investigation_id,
        PHASE_INDEXING,
    )

    try:

        from app.services.rag.indexing_service import (
            rag_indexing_service,
        )

        with session_factory() as db:

            rag_indexing_service.index_investigation(
                investigation_id,
                db,
            )

    except Exception as exc:

        logger.warning(
            "RAG indexing failed for investigation '%s': %s",
            investigation_id,
            exc,
        )


def _run_risk_classification(
    investigation_id: str,
    session_factory=SessionLocal,
) -> None:
    """
    Persist risk levels for an investigation's evidence.

    Runs on the request's background tasks after indexing so a slow or
    failing classification pass never blocks the investigation response.
    Failures are logged and swallowed on purpose.
    """

    investigation_phase_tracker.set(
        investigation_id,
        PHASE_CLASSIFYING,
    )

    try:

        with session_factory() as db:

            classify_investigation_evidence(db, investigation_id)

    except Exception as exc:

        logger.warning(
            "Risk classification failed for investigation '%s': %s",
            investigation_id,
            exc,
        )

    investigation_phase_tracker.set(
        investigation_id,
        PHASE_COMPLETED,
    )


@router.post(
    "/start",
    response_model=InvestigationStartResponse,
)
async def start_investigation(
    request: InvestigationStartRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):

    from app.services.investigation_service import (
        investigation_service,
    )

    investigation_phase_tracker.set(
        request.investigation_id,
        PHASE_VOLATILITY,
    )

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

        memory_dump_record.current_plugin = plugin_name

        memory_dump_repository.update(memory_dump_record)

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

            if result.success and (
                result.json_output or result.json_output_path
            ):

                output_path = result.json_output_path

                try:

                    if output_path is not None:

                        parsed = volatility_json_parser.parse_file(
                            result.plugin,
                            output_path,
                        )

                    else:

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

                finally:

                    if output_path is not None:
                        output_path.unlink(missing_ok=True)

        else:

            logger.error(
                "No execution record found for plugin '%s'.",
                result.plugin,
            )

        completed = index + 1

        memory_dump_record.progress = compute_progress(
            completed,
            total,
        )

        memory_dump_repository.update(memory_dump_record)

        logger.info(
            "Plugin progress: %d/%d (%d%%) - %s",
            completed,
            total,
            memory_dump_record.progress,
            result.plugin,
        )

    try:

        await investigation_service.run_investigation_async(
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

    # Post-processing runs after the response is sent so the caller gets the
    # completed status immediately. Indexing runs before classification so a
    # slow classification pass can never prevent evidence from being indexed.
    background_tasks.add_task(
        _run_evidence_indexing,
        request.investigation_id,
    )
    background_tasks.add_task(
        _run_risk_classification,
        request.investigation_id,
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
    plugin_execution_repository = PluginExecutionRepository(db)

    record = memory_dump_repository.get_by_investigation_id(
        investigation_id
    )

    if record is None:

        return InvestigationStatusResponse(
            investigation_id=investigation_id,
            status="not_found",
            progress=0,
        )

    executions = plugin_execution_repository.get_by_memory_dump(
        record.id
    )

    completed_plugins = sum(
        1
        for execution in executions
        if execution.execution_status == "completed"
    )
    failed_plugins = sum(
        1
        for execution in executions
        if execution.execution_status == "failed"
    )

    failed_with_error = [
        execution
        for execution in executions
        if execution.execution_status == "failed"
        and execution.error_message
    ]

    tracked_phase = investigation_phase_tracker.get(investigation_id)

    if tracked_phase in (
        PHASE_INDEXING,
        PHASE_CLASSIFYING,
        PHASE_COMPLETED,
    ):
        phase = tracked_phase
    elif record.status == "running":
        phase = PHASE_VOLATILITY
    elif record.status == "completed":
        phase = PHASE_COMPLETED
    else:
        phase = None

    return InvestigationStatusResponse(
        investigation_id=investigation_id,
        status=record.status,
        progress=record.progress,
        phase=phase,
        current_plugin=record.current_plugin,
        total_plugins=len(executions),
        completed_plugins=completed_plugins,
        failed_plugins=failed_plugins,
        last_error=(
            failed_with_error[0].error_message
            if failed_with_error
            else None
        ),
    )
