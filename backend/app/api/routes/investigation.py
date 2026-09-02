"""
Investigation API
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings

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
    InvestigationListResponse,
    InvestigationStartRequest,
    InvestigationStartResponse,
    InvestigationStatusResponse,
    InvestigationSummary,
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


def configured_plugins() -> list[str]:
    """
    Return the plugin set to run, from configuration.

    Read per call so a selection saved from the Settings page applies to
    the next investigation without a server restart.
    """

    return list(settings.analysis.plugins)


def compute_progress(
    finished_plugins: int,
    total_plugins: int,
) -> int:
    """
    Compute the investigation progress percentage.

    Progress reflects plugins that have *stopped running*, regardless of
    outcome: a failed plugin is finished work and advances the bar. Never
    elapsed time. 0/10 = 0%, 1/10 = 10%, ..., 10/10 = 100%.

    Parameters
    ----------
    finished_plugins : int
        Number of plugins that have finished, successfully or not.

    total_plugins : int
        Total number of plugins scheduled.

    Returns
    -------
    int
        Progress percentage clamped to [0, 100].
    """

    if total_plugins <= 0:
        return 0

    return min(100, int(finished_plugins / total_plugins * 100))


def estimate_seconds_remaining(
    finished_plugins: int,
    total_plugins: int,
    elapsed_seconds: float,
) -> int | None:
    """
    Estimate remaining runtime from average time per finished plugin.

    Deliberately simple: mean time per finished plugin multiplied by the
    number still outstanding. Returns ``None`` until at least one plugin
    has finished, because there is no basis for an estimate before that.
    """

    if finished_plugins <= 0 or total_plugins <= 0:
        return None

    remaining = max(0, total_plugins - finished_plugins)

    if remaining == 0:
        return 0

    average = elapsed_seconds / finished_plugins

    return int(average * remaining)


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


_background_tasks: set[asyncio.Task] = set()


def _launch_pipeline(
    investigation_id: str,
    memory_dump_path: str,
) -> asyncio.Task:
    """
    Schedule the investigation pipeline on the running event loop.

    The task is kept in a module-level set for its lifetime because asyncio
    holds only a weak reference to running tasks; without a strong
    reference an in-flight investigation can be garbage collected mid-run.
    """

    task = asyncio.create_task(
        _run_investigation_pipeline(
            investigation_id,
            memory_dump_path,
        )
    )

    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    return task


async def _run_investigation_pipeline(
    investigation_id: str,
    memory_dump_path: str,
    session_factory=None,
) -> None:
    """
    Run the full investigation pipeline in the background.

    Owns its own database session because the HTTP request that launched it
    has already returned and its session is closed. Volatility execution,
    evidence persistence, indexing, and risk classification all happen here
    so that ``POST /investigation/start`` never blocks on the analysis.

    All failures are captured onto the memory dump record; this coroutine
    never raises into the event loop.
    """

    from app.services.investigation_service import (
        investigation_service,
    )

    # Resolved here rather than as a default argument so that tests (and any
    # future caller) can substitute a session factory by patching the module.
    if session_factory is None:
        session_factory = SessionLocal

    plugins = configured_plugins()

    investigation_phase_tracker.set(
        investigation_id,
        PHASE_VOLATILITY,
    )
    investigation_phase_tracker.start_run(
        investigation_id,
        len(plugins),
    )

    try:

        with session_factory() as db:

            memory_dump_repository = MemoryDumpRepository(db)
            plugin_execution_repository = PluginExecutionRepository(db)
            plugin_result_repository = PluginResultRepository(db)

            memory_dump_record = (
                memory_dump_repository.get_by_investigation_id(
                    investigation_id
                )
            )

            if memory_dump_record is None:
                logger.error(
                    "Investigation '%s' vanished before analysis started.",
                    investigation_id,
                )
                return

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

                finished = index + 1

                memory_dump_record.progress = compute_progress(
                    finished,
                    total,
                )

                memory_dump_repository.update(memory_dump_record)

                logger.info(
                    "Plugin progress: %d/%d (%d%%) - %s",
                    finished,
                    total,
                    memory_dump_record.progress,
                    result.plugin,
                )

            try:

                await investigation_service.run_investigation_async(
                    memory_dump=Path(memory_dump_path),
                    plugins=plugins,
                    on_plugin_started=on_plugin_started,
                    on_plugin_completed=on_plugin_completed,
                    max_concurrency=settings.analysis.max_concurrency,
                )

            except Exception as exc:

                logger.exception("Investigation failed.")

                memory_dump_record.status = "failed"
                memory_dump_record.current_plugin = None

                memory_dump_repository.update(memory_dump_record)

                investigation_phase_tracker.set(
                    investigation_id,
                    PHASE_COMPLETED,
                )

                return

            memory_dump_record.status = "completed"
            memory_dump_record.progress = 100
            memory_dump_record.current_plugin = None

            memory_dump_repository.update(memory_dump_record)

        # Post-processing. Both helpers are synchronous and open their own
        # sessions, so they run on worker threads to keep the event loop
        # free for status polling. Indexing runs before classification so a
        # slow classification pass can never prevent evidence indexing.
        await asyncio.to_thread(
            _run_evidence_indexing,
            investigation_id,
        )
        await asyncio.to_thread(
            _run_risk_classification,
            investigation_id,
        )

    except Exception:

        logger.exception(
            "Investigation pipeline crashed for '%s'.",
            investigation_id,
        )

        investigation_phase_tracker.set(
            investigation_id,
            PHASE_COMPLETED,
        )


@router.post(
    "/start",
    response_model=InvestigationStartResponse,
    status_code=202,
)
async def start_investigation(
    request: InvestigationStartRequest,
    db: Session = Depends(get_db),
):
    """
    Launch an investigation and return immediately.

    The analysis runs as a background task; callers poll
    ``GET /investigation/status/{id}`` for progress. Returning right away
    means a page refresh mid-run no longer abandons an in-flight request.
    """

    from app.services.investigation_service import (
        investigation_service,
    )

    memory_dump_repository = MemoryDumpRepository(db)
    case_repository = CaseRepository(db)

    memory_dump_record = memory_dump_repository.get_by_investigation_id(
        request.investigation_id
    )

    if memory_dump_record is None:

        if not request.memory_dump_path:
            raise HTTPException(
                status_code=404,
                detail=(
                    "Unknown investigation and no memory dump path supplied."
                ),
            )

        try:
            metadata = investigation_service.prepare_memory_dump(
                Path(request.memory_dump_path),
            )
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(
                status_code=400,
                detail=str(exc),
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

        if memory_dump_record.status == "running":
            raise HTTPException(
                status_code=409,
                detail="This investigation is already running.",
            )

        memory_dump_record.status = "running"
        memory_dump_record.progress = 0
        memory_dump_record.current_plugin = None

        memory_dump_repository.update(memory_dump_record)

    stored_path = memory_dump_record.stored_path

    _launch_pipeline(
        request.investigation_id,
        stored_path,
    )

    return InvestigationStartResponse(
        investigation_id=request.investigation_id,
        status="running",
        message="Investigation started.",
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

    finished_plugins = completed_plugins + failed_plugins

    # Prefer the scheduled plugin count captured when the run started: it is
    # known up front and stays constant, unlike the number of execution rows
    # written so far, which grows as plugins launch and made the denominator
    # move underneath the progress bar. Fall back to the row count for runs
    # that predate this process (e.g. after a restart).
    run = investigation_phase_tracker.get_run(investigation_id)

    total_plugins = run.total_plugins if run else len(executions)

    estimated_seconds_remaining = (
        estimate_seconds_remaining(
            finished_plugins,
            total_plugins,
            time.monotonic() - run.started_at,
        )
        if run and record.status == "running"
        else None
    )

    return InvestigationStatusResponse(
        investigation_id=investigation_id,
        status=record.status,
        progress=record.progress,
        phase=phase,
        current_plugin=record.current_plugin,
        total_plugins=total_plugins,
        finished_plugins=finished_plugins,
        completed_plugins=completed_plugins,
        failed_plugins=failed_plugins,
        estimated_seconds_remaining=estimated_seconds_remaining,
        last_error=(
            failed_with_error[0].error_message
            if failed_with_error
            else None
        ),
        filename=record.filename,
        sha256=record.sha256_hash,
        file_size=record.file_size,
    )


@router.get(
    "",
    response_model=InvestigationListResponse,
)
@router.get(
    "/",
    response_model=InvestigationListResponse,
)
async def list_investigations(
    db: Session = Depends(get_db),
):
    """
    List every investigation, newest first.

    Backs the investigation list page and the shared investigation picker
    used across the chat, evidence, search, and report pages.
    """

    repository = PluginResultRepository(db)

    items = [
        InvestigationSummary(
            investigation_id=row.investigation_id or "",
            filename=row.filename,
            status=row.status,
            progress=row.progress,
            uploaded_at=(
                row.uploaded_at.isoformat() if row.uploaded_at else None
            ),
            evidence_count=row.evidence_count,
            plugin_count=row.plugin_count,
        )
        for row in repository.list_investigations()
        if row.investigation_id
    ]

    return InvestigationListResponse(
        items=items,
        total=len(items),
    )
