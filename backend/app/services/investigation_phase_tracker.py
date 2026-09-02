"""
Investigation Phase Tracker.

Tracks the coarse phase of an investigation in memory so the status
endpoint can report whether the forensic plugins are running, evidence is
being indexed, or risk classification is in progress.

Also tracks per-run scheduling data (how many plugins were scheduled and
when the run started) so the status endpoint can report a stable
denominator and a rough time estimate rather than deriving both from
however many execution rows happen to exist at read time.

This is deliberately process-local: no database schema is involved and a
restart simply falls back to the persisted investigation status. Phases
and run data are only meaningful for the currently running server
instance.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

PHASE_VOLATILITY = "volatility"
PHASE_INDEXING = "indexing"
PHASE_CLASSIFYING = "classifying"
PHASE_COMPLETED = "completed"

TERMINAL_PHASES = (PHASE_COMPLETED,)


@dataclass(slots=True)
class RunInfo:
    """
    Scheduling data for one in-flight investigation run.

    ``total_plugins`` is the number of plugins scheduled up front, which is
    known before any of them start and therefore never grows mid-run.
    """

    total_plugins: int

    started_at: float


class InvestigationPhaseTracker:
    """
    In-memory mapping of ``investigation_id`` -> current phase and run data.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._phases: dict[str, str] = {}
        self._runs: dict[str, RunInfo] = {}

    def start_run(
        self,
        investigation_id: str,
        total_plugins: int,
    ) -> None:
        """Record the scheduled plugin count and start time for a run."""

        with self._lock:
            self._runs[investigation_id] = RunInfo(
                total_plugins=total_plugins,
                started_at=time.monotonic(),
            )

    def get_run(
        self,
        investigation_id: str,
    ) -> RunInfo | None:
        """Return run data for an investigation, or ``None`` if unknown."""

        with self._lock:
            return self._runs.get(investigation_id)

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
        """Remove any recorded phase and run data for an investigation."""

        with self._lock:
            self._phases.pop(investigation_id, None)
            self._runs.pop(investigation_id, None)


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
    "RunInfo",
    "investigation_phase_tracker",
]
