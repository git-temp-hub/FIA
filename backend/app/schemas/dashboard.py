"""
Dashboard Schemas for the AI Memory Forensic Investigation Assistant.

Defines the response contracts for live dashboard statistics.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class DashboardRecentInvestigation(BaseModel):
    """
    Summary for a single investigation on the dashboard.
    """

    investigation_id: str
    filename: str
    status: str
    progress: int
    uploaded_at: datetime
    evidence_count: int


class DashboardTrendPoint(BaseModel):
    """
    A single point in the investigation trend series.
    """

    day: str
    label: str
    investigations: int


class DashboardEvidenceDistribution(BaseModel):
    """
    Artifact type distribution entry.
    """

    artifact_type: str
    count: int


class SystemHealth(BaseModel):
    """
    Live system health status.
    """

    application: str
    version: str
    environment: str
    database: str
    ollama: str
    chromadb: str


class DashboardStatsResponse(BaseModel):
    """
    Aggregate dashboard statistics.
    """

    total_investigations: int
    total_memory_dumps: int
    total_evidence: int
    total_reports: int
    total_ai_queries: int
    plugin_executions_total: int
    plugin_execution_success_rate: float
    recent_investigations: list[DashboardRecentInvestigation]
    investigation_trend: list[DashboardTrendPoint]
    evidence_distribution: list[DashboardEvidenceDistribution]
    system_health: SystemHealth


__all__ = [
    "DashboardStatsResponse",
    "DashboardRecentInvestigation",
    "DashboardTrendPoint",
    "DashboardEvidenceDistribution",
    "SystemHealth",
]
