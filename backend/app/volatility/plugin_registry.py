"""
Plugin Registry for the AI Memory Forensic Investigation Assistant.

This module maintains the centralized registry of supported
Volatility 3 plugins used by the FIA platform.

Author:
    FIA Development Team
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final

from app.core.logging import get_logger

logger = get_logger(__name__)


# ==============================================================================
# Plugin Categories
# ==============================================================================


class PluginCategory(str, Enum):
    """
    Categories of supported Volatility plugins.
    """

    PROCESS = "process"

    NETWORK = "network"

    REGISTRY = "registry"

    FILESYSTEM = "filesystem"

    KERNEL = "kernel"

    MEMORY = "memory"

    MALWARE = "malware"

    SYSTEM = "system"


# ==============================================================================
# Plugin Metadata
# ==============================================================================


@dataclass(slots=True, frozen=True)
class PluginMetadata:
    """
    Metadata describing a Volatility plugin.
    """

    name: str

    category: PluginCategory

    description: str

    produces_json: bool = True

    enabled: bool = True


# ==============================================================================
# Plugin Registry
# ==============================================================================


class PluginRegistry:
    """
    Central registry of all supported Volatility plugins.
    """

    def __init__(self) -> None:
        self._plugins: dict[str, PluginMetadata] = {}

        logger.info(
            "Plugin Registry initialized."
        )
        self.register_default_plugins()

    # ------------------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------------------

    def register_plugin(
        self,
        plugin: PluginMetadata,
    ) -> None:
        """
        Register a Volatility plugin.
        """

        self._plugins[plugin.name] = plugin

        logger.debug(
            "Registered plugin: %s",
            plugin.name,
        )

    def register_default_plugins(self) -> None:
        """
        Register all default FIA-supported Volatility plugins.
        """

        default_plugins = [
            PluginMetadata(
                name="windows.pslist",
                category=PluginCategory.PROCESS,
                description="List active processes.",
            ),
            PluginMetadata(
                name="windows.pstree",
                category=PluginCategory.PROCESS,
                description="Display process hierarchy.",
            ),
            PluginMetadata(
                name="windows.cmdline",
                category=PluginCategory.PROCESS,
                description="Extract process command lines.",
            ),
            PluginMetadata(
                name="windows.dlllist",
                category=PluginCategory.PROCESS,
                description="List loaded DLLs.",
            ),
            PluginMetadata(
                name="windows.handles",
                category=PluginCategory.PROCESS,
                description="Enumerate process handles.",
            ),
            PluginMetadata(
                name="windows.netscan",
                category=PluginCategory.NETWORK,
                description="Scan network connections.",
            ),
            PluginMetadata(
                name="windows.filescan",
                category=PluginCategory.FILESYSTEM,
                description="Recover file objects.",
            ),
            PluginMetadata(
                name="windows.registry.printkey",
                category=PluginCategory.REGISTRY,
                description="Read registry keys.",
            ),
            PluginMetadata(
                name="windows.malfind",
                category=PluginCategory.MALWARE,
                description="Detect suspicious injected memory.",
            ),
            PluginMetadata(
                name="windows.info",
                category=PluginCategory.SYSTEM,
                description="System information.",
            ),
        ]

        for plugin in default_plugins:
            self.register_plugin(plugin)

        logger.info(
            "Registered %d default plugins.",
            len(default_plugins),
        )

    # ------------------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------------------

    def get_plugin(
        self,
        plugin_name: str,
    ) -> PluginMetadata:
        """
        Return metadata for a single plugin.

        Raises
        ------
        KeyError
            If the plugin is not registered.
        """

        try:
            return self._plugins[plugin_name]

        except KeyError as exc:
            raise KeyError(
                f"Plugin '{plugin_name}' is not registered."
            ) from exc

    def has_plugin(
        self,
        plugin_name: str,
    ) -> bool:
        """
        Check whether a plugin exists.
        """

        return plugin_name in self._plugins

    def list_plugins(self) -> list[PluginMetadata]:
        """
        Return all registered plugins.
        """

        return list(self._plugins.values())

    def list_plugin_names(self) -> list[str]:
        """
        Return registered plugin names.
        """

        return sorted(self._plugins.keys())

    # ------------------------------------------------------------------------------
    # Category Queries
    # ------------------------------------------------------------------------------

    def get_plugins_by_category(
        self,
        category: PluginCategory,
    ) -> list[PluginMetadata]:
        """
        Return plugins belonging to a category.
        """

        return [
            plugin
            for plugin in self._plugins.values()
            if plugin.category == category
        ]

    # ------------------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------------------

    def validate_plugin(
        self,
        plugin_name: str,
    ) -> None:
        """
        Validate that a plugin exists and is enabled.

        Raises
        ------
        ValueError
            If the plugin is unavailable.
        """

        plugin = self.get_plugin(plugin_name)

        if not plugin.enabled:
            raise ValueError(
                f"Plugin '{plugin_name}' is disabled."
            )

# ==============================================================================
# Singleton Instance
# ==============================================================================

plugin_registry = PluginRegistry()


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "PluginCategory",
    "PluginMetadata",
    "PluginRegistry",
    "plugin_registry",
]


