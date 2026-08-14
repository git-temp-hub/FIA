"""
Investigation Phase Tracker.

Tracks the coarse phase of an investigation in memory so the status
endpoint can report whether the forensic plugins are running, evidence is
being indexed, or risk classification is in progress.

This is deliberately process-local: no database schema is involved and a
restart simply falls back to the persisted investigation status. Phases
are only meaningful for the currently running server instance.
"""

from __future__ import annotations

import threading

PHASE_VOLATILITY = "volatility"
PHASE_INDEXING = "indexing"
PHASE_CLASSIFYING = "classifying"
PHASE_COMPLETED = "completed"

TERMINAL_PHASES = (PHASE_COMPLETED,)


class InvestigationPhaseTracker:
    """
    In-memory mapping of ``investigation_id`` -> current phase.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._phases: dict[str, str] = {}

    def set(
        self,
        investigation_id: str,
        phase: str,
    ) -> None:
        """Record the current phase for an investigation."""

        with self._lock:
            self._phases[investigation_id] = phase

    def get(
        self,
        investigation_id: str,
    ) -> str | None:
        """Return the recorded phase, or ``None`` if unknown."""

        with self._lock:
            return self._phases.get(investigation_id)

    def clear(
        self,
        investigation_id: str,
    ) -> None:
        """Remove any recorded phase for an investigation."""

        with self._lock:
            self._phases.pop(investigation_id, None)


# ==============================================================================
# Singleton Instance
# ==============================================================================

investigation_phase_tracker = InvestigationPhaseTracker()

# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "PHASE_VOLATILITY",
    "PHASE_INDEXING",
    "PHASE_CLASSIFYING",
    "PHASE_COMPLETED",
    "TERMINAL_PHASES",
    "InvestigationPhaseTracker",
    "investigation_phase_tracker",
]
