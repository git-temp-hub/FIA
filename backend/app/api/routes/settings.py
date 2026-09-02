"""
Settings API

Exposes the runtime-editable subset of platform configuration and persists
changes back to ``configs/config.yaml``.

Precedence note
---------------
Environment variables override config.yaml (conventional 12-factor
ordering, see ``app.core.config.environment_overrides``). The ``analysis``
and ``upload`` sections have no environment counterpart, so values saved
here are always the effective values. ``ollama.model`` / ``ollama.base_url``
do have counterparts (LLM_MODEL / OLLAMA_HOST); when one of those is set,
the write still persists but the response reports it in ``env_shadowed``
so the UI can say the saved value is not currently in effect.
"""

from __future__ import annotations

import io
import os
from typing import Any

from fastapi import APIRouter, HTTPException
from ruamel.yaml import YAML

from app.core.config import CONFIG_FILE, reload_settings, settings
from app.core.logging import get_logger
from app.schemas.settings import (
    AnalysisSettingsPayload,
    LLMSettingsPayload,
    SettingsResponse,
    SettingsUpdateRequest,
    StoragePathsView,
    UploadSettingsPayload,
)
from app.volatility.plugin_registry import plugin_registry

logger = get_logger(__name__)

router = APIRouter(
    prefix="/settings",
    tags=["Settings"],
)


def _yaml() -> YAML:
    """
    Return a round-trip YAML handler.

    Round-trip mode preserves comments, key order, and formatting, so the
    explanatory comments in config.yaml survive a settings write. A plain
    ``yaml.safe_dump`` would silently strip every comment in the file.
    """

    handler = YAML(typ="rt")
    handler.preserve_quotes = True
    handler.indent(mapping=2, sequence=4, offset=2)

    return handler


def _read_config_file() -> Any:
    """
    Load config.yaml, retaining comments and formatting for round-tripping.
    """

    if not CONFIG_FILE.exists():
        raise HTTPException(
            status_code=500,
            detail="Configuration file is missing.",
        )

    with CONFIG_FILE.open("r", encoding="utf-8") as handle:
        return _yaml().load(handle) or {}


def _write_config_file(document: Any) -> None:
    """
    Persist the config document, writing atomically.

    The document is serialised into memory first so a serialisation failure
    cannot leave a partially written file, then a temporary file in the same
    directory is replaced over the original.
    """

    buffer = io.StringIO()
    _yaml().dump(document, buffer)

    temporary = CONFIG_FILE.with_suffix(".yaml.tmp")

    try:

        temporary.write_text(buffer.getvalue(), encoding="utf-8")

        os.replace(temporary, CONFIG_FILE)

    finally:

        temporary.unlink(missing_ok=True)


def _set_sequence_preserving_comment(
    mapping: Any,
    key: str,
    values: list[str],
) -> None:
    """
    Replace a YAML sequence without losing the comment that follows it.

    ruamel attaches a comment sitting between a sequence and the next key to
    the sequence's *last index*. Writing a shorter list therefore orphans
    that comment and silently deletes it from the file. The comment is
    captured before the rewrite and re-attached to the new final index.
    """

    existing = mapping.get(key)

    trailing = None

    if existing is not None and hasattr(existing, "ca"):
        last_index = len(existing) - 1
        trailing = existing.ca.items.pop(last_index, None)

    if isinstance(existing, list):
        existing[:] = values
        target = existing
    else:
        mapping[key] = values
        target = mapping[key]

    if trailing is not None and hasattr(target, "ca") and len(target) > 0:
        target.ca.items[len(target) - 1] = trailing


def _env_shadowed() -> list[str]:
    """Return the names of settings currently overridden by the env."""

    shadowed: list[str] = []

    if os.getenv("LLM_MODEL"):
        shadowed.append("llm.model")

    if os.getenv("OLLAMA_HOST"):
        shadowed.append("llm.base_url")

    return shadowed


def _current_settings_response() -> SettingsResponse:
    """Build the settings response from the live configuration."""

    return SettingsResponse(
        analysis=AnalysisSettingsPayload(
            plugins=list(settings.analysis.plugins),
            plugin_timeout_seconds=(
                settings.analysis.plugin_timeout_seconds
            ),
            max_concurrency=settings.analysis.max_concurrency,
        ),
        upload=UploadSettingsPayload(
            max_dump_size_gb=settings.upload.max_dump_size_gb,
        ),
        llm=LLMSettingsPayload(
            model=settings.ollama.model,
            base_url=settings.ollama.base_url,
        ),
        storage=StoragePathsView(
            database=str(settings.database.path),
            vectors=str(settings.vector_database.path),
            uploads=str(settings.storage.uploads),
            reports=str(settings.reporting.output_directory),
        ),
        available_plugins=sorted(plugin_registry.list_plugin_names()),
        env_shadowed=_env_shadowed(),
    )


@router.get(
    "",
    response_model=SettingsResponse,
)
@router.get(
    "/",
    response_model=SettingsResponse,
)
async def get_settings_endpoint():
    """Return the effective platform settings."""

    return _current_settings_response()


@router.put(
    "",
    response_model=SettingsResponse,
)
@router.put(
    "/",
    response_model=SettingsResponse,
)
async def update_settings(request: SettingsUpdateRequest):
    """
    Persist a partial settings update to config.yaml.

    Field-level bounds are enforced by the request schema; this handler adds
    the cross-field checks that Pydantic cannot express on its own.
    """

    document = _read_config_file()

    if request.analysis is not None:

        unknown = [
            name
            for name in request.analysis.plugins
            if not plugin_registry.has_plugin(name)
        ]

        if unknown:
            raise HTTPException(
                status_code=422,
                detail=(
                    "Unknown plugin(s): " + ", ".join(sorted(unknown))
                ),
            )

        analysis = document.setdefault("analysis", {})

        _set_sequence_preserving_comment(
            analysis,
            "plugins",
            list(request.analysis.plugins),
        )

        analysis["plugin_timeout_seconds"] = (
            request.analysis.plugin_timeout_seconds
        )
        analysis["max_concurrency"] = request.analysis.max_concurrency

    if request.upload is not None:

        upload = document.setdefault("upload", {})
        upload["max_dump_size_gb"] = request.upload.max_dump_size_gb

    if request.llm is not None:

        base_url = request.llm.base_url.strip()

        if not base_url.startswith(("http://", "https://")):
            raise HTTPException(
                status_code=422,
                detail="Ollama host must start with http:// or https://",
            )

        ollama = document.setdefault("ollama", {})
        ollama["model"] = request.llm.model.strip()
        ollama["base_url"] = base_url

    _write_config_file(document)

    reload_settings()

    logger.info("Platform settings updated.")

    return _current_settings_response()


__all__ = ["router"]
