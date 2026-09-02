"""
Investigation API Schemas
"""

from __future__ import annotations

from pydantic import BaseModel


class InvestigationStartRequest(BaseModel):
    """
    Request to start (or restart) an investigation.

    ``memory_dump_path`` is only needed when no record exists yet for the
    investigation; for a known investigation the stored path is resolved
    from the database, so callers arriving from the investigation list do
    not need to carry the path around.
    """

    investigation_id: str
    memory_dump_path: str | None = None


class InvestigationStartResponse(BaseModel):
    investigation_id: str
    status: str
    message: str


class InvestigationStatusResponse(BaseModel):
    """
    Progress snapshot for one investigation.

    Progress semantics: ``progress`` and ``finished_plugins`` both count
    plugins that have *stopped running*, regardless of outcome. A plugin
    that failed still represents completed work and still advances the bar.
    ``completed_plugins`` / ``failed_plugins`` break that total down by
    outcome and are reported alongside it rather than competing with it.
    """

    investigation_id: str
    status: str
    progress: int
    phase: str | None = None
    current_plugin: str | None = None
    total_plugins: int = 0
    finished_plugins: int = 0
    completed_plugins: int = 0
    failed_plugins: int = 0
    estimated_seconds_remaining: int | None = None
    last_error: str | None = None

    # Dump identity, so a client reaching the detail view by any route can
    # render the investigation fully from this response alone. Previously
    # these lived only in router state handed over by the upload page, so
    # navigating away and back lost the filename and hash.
    filename: str | None = None
    sha256: str | None = None
    file_size: int | None = None


class InvestigationSummary(BaseModel):
    """One row in the investigation list."""

    investigation_id: str
    filename: str
    status: str
    progress: int
    uploaded_at: str | None = None
    evidence_count: int = 0
    plugin_count: int = 0


class InvestigationListResponse(BaseModel):
    items: list[InvestigationSummary]
    total: int
