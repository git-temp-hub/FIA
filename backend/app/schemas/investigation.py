"""
Investigation API Schemas
"""

from __future__ import annotations

from pydantic import BaseModel


class InvestigationStartRequest(BaseModel):
    investigation_id: str
    memory_dump_path: str


class InvestigationStartResponse(BaseModel):
    investigation_id: str
    status: str
    message: str


class InvestigationStatusResponse(BaseModel):
    investigation_id: str
    status: str
    progress: int
    phase: str | None = None
    current_plugin: str | None = None
    total_plugins: int = 0
    completed_plugins: int = 0
    failed_plugins: int = 0
    last_error: str | None = None