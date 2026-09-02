"""
Settings API Schemas

Covers the runtime-editable subset of platform configuration. Storage and
report paths are deliberately excluded from the writable surface: changing
them at runtime would orphan already-stored evidence and reports.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class AnalysisSettingsPayload(BaseModel):
    """Editable Volatility analysis settings."""

    plugins: list[str] = Field(..., min_length=1)

    plugin_timeout_seconds: int = Field(..., ge=30, le=86_400)

    max_concurrency: int = Field(..., ge=1, le=32)


class UploadSettingsPayload(BaseModel):
    """Editable upload limits."""

    max_dump_size_gb: int = Field(..., ge=1, le=1024)


class LLMSettingsPayload(BaseModel):
    """Editable LLM connection settings."""

    model: str = Field(..., min_length=1, max_length=200)

    base_url: str = Field(..., min_length=1, max_length=500)


class SettingsUpdateRequest(BaseModel):
    """
    Partial settings update.

    Every section is optional; only the sections supplied are written.
    """

    analysis: AnalysisSettingsPayload | None = None

    upload: UploadSettingsPayload | None = None

    llm: LLMSettingsPayload | None = None


class StoragePathsView(BaseModel):
    """Read-only storage locations."""

    database: str
    vectors: str
    uploads: str
    reports: str


class SettingsResponse(BaseModel):
    """
    Effective platform settings.

    ``env_shadowed`` names settings whose configured value is currently
    overridden by an environment variable. Those writes still persist to
    config.yaml, but the environment wins until it is cleared, so the UI
    surfaces the discrepancy instead of silently showing a value that is
    not actually in effect.
    """

    analysis: AnalysisSettingsPayload

    upload: UploadSettingsPayload

    llm: LLMSettingsPayload

    storage: StoragePathsView

    available_plugins: list[str]

    env_shadowed: list[str] = []


__all__ = [
    "AnalysisSettingsPayload",
    "UploadSettingsPayload",
    "LLMSettingsPayload",
    "SettingsUpdateRequest",
    "StoragePathsView",
    "SettingsResponse",
]
