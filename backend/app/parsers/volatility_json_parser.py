"""
Volatility JSON Parser for the AI Memory Forensic Investigation Assistant.

This module parses JSON output produced by Volatility 3 plugins and
converts it into validated Python structures.

Author:
    FIA Development Team
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)


# ==============================================================================
# Parser Result
# ==============================================================================


@dataclass(slots=True)
class ParsedPluginOutput:
    """
    Represents parsed JSON output from a Volatility plugin.
    """

    plugin: str

    rows: list[dict[str, Any]]

    row_count: int


# ==============================================================================
# Volatility JSON Parser
# ==============================================================================


class VolatilityJSONParser:
    """
    Parses Volatility JSON output.
    """

    def __init__(self) -> None:
        logger.info(
            "Volatility JSON Parser initialized."
        )
    # --------------------------------------------------------------------------
    # JSON Loading
    # --------------------------------------------------------------------------

    def load_json(
        self,
        raw_json: str,
    ) -> Any:
        """
        Parse a raw JSON string produced by Volatility.

        Raises
        ------
        ValueError
            If the JSON is invalid.
        """

        try:
            data = json.loads(raw_json)

        except json.JSONDecodeError as exc:
            logger.exception("Invalid Volatility JSON.")

            raise ValueError(
                "Invalid Volatility JSON output."
            ) from exc

        return data

    # --------------------------------------------------------------------------
    # Validation
    # --------------------------------------------------------------------------

    def validate_rows(
        self,
        data: Any,
    ) -> list[dict[str, Any]]:
        """
        Validate that the parsed JSON contains a list of rows.
        """

        if not isinstance(data, list):
            raise ValueError(
                "Expected Volatility JSON output to be a list."
            )

        rows: list[dict[str, Any]] = []

        for item in data:
            if isinstance(item, dict):
                rows.append(item)

        return rows
    # --------------------------------------------------------------------------
    # Main Parser
    # --------------------------------------------------------------------------

    def parse(
        self,
        plugin_name: str,
        raw_json: str,
    ) -> ParsedPluginOutput:
        """
        Parse and validate Volatility JSON output.
        """

        data = self.load_json(raw_json)

        rows = self.validate_rows(data)

        parsed = ParsedPluginOutput(
            plugin=plugin_name,
            rows=rows,
            row_count=len(rows),
        )

        logger.info(
            "Parsed %d rows from plugin '%s'.",
            parsed.row_count,
            plugin_name,
        )

        return parsed

    def parse_file(
        self,
        plugin_name: str,
        output_path: Path,
    ) -> ParsedPluginOutput:
        """
        Parse and validate Volatility JSON output from a file on disk.

        Reads the streamed plugin output (see ``PluginRunner``) once and
        parses it, so the JSON text is only loaded into memory for the
        duration of the parse rather than retained for the whole execution.
        """

        if not output_path.exists():
            raise ValueError(
                f"Volatility output file not found: {output_path}"
            )

        raw_json = output_path.read_text(
            encoding="utf-8",
            errors="replace",
        )

        return self.parse(
            plugin_name=plugin_name,
            raw_json=raw_json,
        )
# ==============================================================================
# Singleton Instance
# ==============================================================================

volatility_json_parser = VolatilityJSONParser()

# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "ParsedPluginOutput",
    "VolatilityJSONParser",
    "volatility_json_parser",
]
