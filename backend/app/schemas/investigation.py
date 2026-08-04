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