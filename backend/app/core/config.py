"""
Configuration Manager for the AI Memory Forensic Investigation Assistant (FIA).

This module centralizes application configuration by loading values from:

1. Default configuration
2. backend/configs/config.yaml
3. backend/.env

Priority:
Environment Variables > config.yaml > Defaults

Every FIA module should import only:

    from app.core.config import settings

Author:
    FIA Development Team
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict


# ==============================================================================
# Project Path Resolution
# ==============================================================================

CURRENT_FILE = Path(__file__).resolve()

CORE_DIR = CURRENT_FILE.parent

APP_DIR = CORE_DIR.parent

BACKEND_DIR = APP_DIR.parent

PROJECT_ROOT = BACKEND_DIR.parent

CONFIG_DIR = BACKEND_DIR / "configs"

STORAGE_DIR = BACKEND_DIR / "storage"

UPLOAD_DIR = STORAGE_DIR / "uploads"

PARSED_DIR = STORAGE_DIR / "parsed"

VECTOR_DIR = STORAGE_DIR / "vectors"

REPORT_DIR = STORAGE_DIR / "reports"

DATABASE_DIR = STORAGE_DIR / "database"

TEMP_DIR = STORAGE_DIR / "temp"

ENV_FILE = BACKEND_DIR / ".env"

CONFIG_FILE = CONFIG_DIR / "config.yaml"

LOGGING_CONFIG_FILE = CONFIG_DIR / "logging.yaml"


# ==============================================================================
# Configuration Models
# ==============================================================================


class ApplicationSettings(BaseModel):
    """General application configuration."""

    name: str = Field(...)

    version: str = Field(...)

    environment: str = Field(...)


class ServerSettings(BaseModel):
    """FastAPI server configuration."""

    host: str = Field(...)

    port: int = Field(...)


class DatabaseSettings(BaseModel):
    """SQLite configuration."""

    path: Path


class VectorDatabaseSettings(BaseModel):
    """Vector database configuration."""

    path: Path


class OllamaSettings(BaseModel):
    """Local LLM configuration."""

    base_url: str

    model: str


class LoggingSettings(BaseModel):
    """Logging configuration."""

    level: str

    config_path: Path


class ReportingSettings(BaseModel):
    """Report generation configuration."""

    output_directory: Path


class StorageSettings(BaseModel):
    """Application storage directories."""

    uploads: Path

    parsed: Path

    vectors: Path

    reports: Path

    database: Path

    temp: Path


class FeatureSettings(BaseModel):
    """
    Feature toggles.

    Useful for future enterprise and research versions.
    """

    rag: bool = True

    reporting: bool = True

    api: bool = True

    volatility: bool = True


class ToolSettings(BaseModel):
    """
    Digital forensic engine configuration.

    Future versions can enable more tools here.
    """

    volatility: bool = True

    rekall: bool = False

    autopsy: bool = False

    velociraptor: bool = False

    yara: bool = False


class RAGSettings(BaseModel):
    """
    Retrieval-Augmented Generation configuration.

    ``index_batch_size`` bounds how many evidence rows are read, embedded,
    and written per index page; ``embed_batch_size`` bounds how many documents
    are passed to the embedding model per encode call. Both keep memory
    bounded on large investigations.
    """

    index_batch_size: int = Field(1000, ge=1, le=5461)

    embed_batch_size: int = Field(64, ge=1)

# ==============================================================================
# Root Settings
# ==============================================================================


class Settings(BaseSettings):
    """
    Central application configuration.

    Every module should import the singleton:

        from app.core.config import settings
    """

    application: ApplicationSettings

    server: ServerSettings

    database: DatabaseSettings

    vector_database: VectorDatabaseSettings

    ollama: OllamaSettings

    logging: LoggingSettings

    reporting: ReportingSettings

    storage: StorageSettings

    features: FeatureSettings = FeatureSettings()

    tools: ToolSettings = ToolSettings()

    rag: RAGSettings = RAGSettings()

    model_config = SettingsConfigDict(
        extra="ignore",
        validate_assignment=True,
    )


# ==============================================================================
# Configuration Loading
# ==============================================================================


def load_yaml_config() -> dict[str, Any]:
    """
    Load backend/configs/config.yaml.
    """

    if not CONFIG_FILE.exists():
        raise FileNotFoundError(
            f"Configuration file not found:\n{CONFIG_FILE}"
        )

    with CONFIG_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:

        data = yaml.safe_load(file)

    return data or {}


def load_environment() -> None:
    """
    Load .env file if present.

    Missing .env is allowed because production
    environments may inject variables directly.
    """

    if ENV_FILE.exists():
        load_dotenv(ENV_FILE)


# ==============================================================================
# Environment Overrides
# ==============================================================================


def environment_overrides() -> dict[str, Any]:
    """
    Build configuration overrides from environment variables.

    Environment variables always override YAML.
    """

    import os

    return {

        "application": {

            "name": os.getenv("APP_NAME"),

            "version": os.getenv("APP_VERSION"),

            "environment": os.getenv("ENVIRONMENT"),
        },

        "server": {

            "host": os.getenv("HOST"),

            "port": (
                int(os.getenv("PORT"))
                if os.getenv("PORT")
                else None
            ),
        },

        "database": {

            "path": os.getenv("DATABASE_PATH"),
        },

        "vector_database": {

            "path": os.getenv("VECTOR_DB_PATH"),
        },

        "ollama": {

            "base_url": os.getenv("OLLAMA_HOST"),

            "model": os.getenv("LLM_MODEL"),
        },

        "logging": {

            "level": os.getenv("LOG_LEVEL"),

            "config_path": os.getenv("LOGGING_CONFIG_PATH"),
        },

        "reporting": {

            "output_directory": os.getenv("REPORT_DIRECTORY"),
        },

        "rag": _rag_environment_overrides(),

    }


def _rag_environment_overrides() -> dict[str, int]:
    """
    Build RAG environment overrides, including only values that are set.

    ``deep_merge`` copies whole sections wholesale when the section is absent
    from config.yaml, so absent values must not appear as ``None`` here.
    """

    import os

    overrides: dict[str, int] = {}

    if os.getenv("RAG_INDEX_BATCH_SIZE"):
        overrides["index_batch_size"] = int(
            os.getenv("RAG_INDEX_BATCH_SIZE")
        )

    if os.getenv("RAG_EMBED_BATCH_SIZE"):
        overrides["embed_batch_size"] = int(
            os.getenv("RAG_EMBED_BATCH_SIZE")
        )

    return overrides

# ==============================================================================
# Dictionary Merge Utilities
# ==============================================================================


def deep_merge(
    base: dict[str, Any],
    override: dict[str, Any],
) -> dict[str, Any]:
    """
    Recursively merge two dictionaries.

    Non-null values from the override dictionary replace values
    in the base dictionary.
    """

    merged = dict(base)

    for key, value in override.items():

        if value is None:
            continue

        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = deep_merge(
                merged[key],
                value,
            )

        else:
            merged[key] = value

    return merged


# ==============================================================================
# Path Resolution
# ==============================================================================


def resolve_path(value: str | Path | None) -> Path | None:
    """
    Convert a configured path into an absolute Path.

    Relative paths are resolved relative to BACKEND_DIR.
    """

    if value is None:
        return None

    path = Path(value)

    if not path.is_absolute():
        path = BACKEND_DIR / path

    return path.resolve()


def resolve_paths(config: dict[str, Any]) -> dict[str, Any]:
    """
    Resolve all filesystem paths inside the configuration.
    """

    path_fields = [
        ("database", "path"),
        ("vector_database", "path"),
        ("logging", "config_path"),
        ("reporting", "output_directory"),
    ]

    for section, field in path_fields:

        section_data = config.get(section)

        if not section_data:
            continue

        if field not in section_data:
            continue

        section_data[field] = resolve_path(
            section_data[field]
        )

    return config


# ==============================================================================
# Storage Configuration
# ==============================================================================


def build_storage_configuration() -> dict[str, Path]:
    """
    Build the storage section automatically.

    Users should never manually edit storage paths.
    """

    return {
        "uploads": UPLOAD_DIR,
        "parsed": PARSED_DIR,
        "vectors": VECTOR_DIR,
        "reports": REPORT_DIR,
        "database": DATABASE_DIR,
        "temp": TEMP_DIR,
    }


# ==============================================================================
# Configuration Builder
# ==============================================================================


def build_configuration() -> dict[str, Any]:
    """
    Construct the complete application configuration.

    Priority

        Defaults
            ↓
        config.yaml
            ↓
        .env
    """

    yaml_configuration = load_yaml_config()

    load_environment()

    env_configuration = environment_overrides()

    configuration = deep_merge(
        yaml_configuration,
        env_configuration,
    )

    configuration = resolve_paths(
        configuration,
    )

    configuration["storage"] = (
        build_storage_configuration()
    )

    return configuration

# ==============================================================================
# Validation
# ==============================================================================


def validate_configuration(configuration: dict[str, Any]) -> Settings:
    """
    Validate the complete configuration using Pydantic.
    """

    try:
        return Settings(**configuration)

    except ValidationError as exc:
        raise RuntimeError(
            "Invalid FIA configuration.\n\n"
            f"{exc}"
        ) from exc


# ==============================================================================
# Startup Verification
# ==============================================================================


def create_required_directories(settings: Settings) -> None:
    """
    Ensure all required directories exist.
    """

    directories = [
        settings.storage.uploads,
        settings.storage.parsed,
        settings.storage.vectors,
        settings.storage.reports,
        settings.storage.database,
        settings.storage.temp,
        settings.reporting.output_directory,
        settings.database.path.parent,
        settings.vector_database.path,
    ]

    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)


def verify_configuration(settings: Settings) -> None:
    """
    Perform additional runtime validation.
    """

    if not settings.application.name:
        raise RuntimeError(
            "Application name is missing."
        )

    if not settings.application.version:
        raise RuntimeError(
            "Application version is missing."
        )

    if settings.server.port <= 0 or settings.server.port > 65535:
        raise RuntimeError(
            f"Invalid server port: {settings.server.port}"
        )

    if not settings.ollama.base_url:
        raise RuntimeError(
            "OLLAMA_BASE_URL is not configured."
        )

    if not settings.ollama.model:
        raise RuntimeError(
            "OLLAMA_MODEL is not configured."
        )

    if not settings.logging.config_path.exists():
        raise RuntimeError(
            "Logging configuration file does not exist:\n"
            f"{settings.logging.config_path}"
        )


# ==============================================================================
# Singleton
# ==============================================================================


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the singleton application settings.

    The configuration is loaded only once during the application lifecycle.
    """

    configuration = build_configuration()

    settings = validate_configuration(configuration)

    create_required_directories(settings)

    verify_configuration(settings)

    return settings


settings = get_settings()


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "settings",
    "get_settings",
    "Settings",
    "ApplicationSettings",
    "ServerSettings",
    "DatabaseSettings",
    "VectorDatabaseSettings",
    "OllamaSettings",
    "LoggingSettings",
    "ReportingSettings",
    "StorageSettings",
    "FeatureSettings",
    "ToolSettings",
    "RAGSettings",
    "PROJECT_ROOT",
    "BACKEND_DIR",
    "APP_DIR",
    "CORE_DIR",
    "CONFIG_DIR",
    "STORAGE_DIR",
    "UPLOAD_DIR",
    "PARSED_DIR",
    "VECTOR_DIR",
    "REPORT_DIR",
    "DATABASE_DIR",
    "TEMP_DIR",
]
