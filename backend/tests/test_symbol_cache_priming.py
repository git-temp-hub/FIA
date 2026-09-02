"""
Regression test for Volatility symbol-cache priming.

Volatility builds its kernel symbol table into a shared on-disk cache the
first time it analyses a given dump. On Windows, a plugin that opens that
cache while another process is still writing it fails with
``PermissionError: [WinError 32]`` and reports "Unable to validate the
plugin requirements". When every plugin launches at once, all but the one
building the cache fail, and a perfectly valid memory dump yields zero
evidence.

The execution service therefore runs the first plugin alone before
parallelising the rest. These tests pin that ordering.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import threading
import time
import types
from pathlib import Path

import pytest


# The service imports Volatility machinery at module load; stub the pieces
# that would otherwise require a real Volatility installation.
_execution_engine_stub = types.ModuleType("app.volatility.execution_engine")


class ExecutionResult:  # noqa: D101 - test double
    def __init__(
        self,
        plugin: str,
        success: bool = True,
        return_code: int = 0,
        stdout: str = "",
        stderr: str = "",
        json_output=None,
        json_output_path=None,
    ) -> None:
        self.plugin = plugin
        self.success = success
        self.return_code = return_code
        self.stdout = stdout
        self.stderr = stderr
        self.json_output = json_output
        self.json_output_path = json_output_path


_execution_engine_stub.ExecutionResult = ExecutionResult  # type: ignore[attr-defined]
_execution_engine_stub.execution_engine = object()  # type: ignore[attr-defined]

sys.modules.setdefault(
    "app.volatility.execution_engine",
    _execution_engine_stub,
)

def _load_real_investigation_service():
    """
    Load the real service module from source.

    ``test_investigation_progress`` installs a stub into
    ``sys.modules["app.services.investigation_service"]`` at import time, so a
    plain import here would resolve to that stub depending on collection
    order. Loading from the file under a private name keeps this module
    independent of test ordering without disturbing the stub other tests rely
    on.
    """

    module_path = (
        Path(__file__).resolve().parents[1]
        / "app"
        / "services"
        / "investigation_service.py"
    )

    spec = importlib.util.spec_from_file_location(
        "_fia_investigation_service_under_test",
        module_path,
    )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]

    return module


InvestigationService = _load_real_investigation_service().InvestigationService


@pytest.mark.asyncio
async def test_first_plugin_runs_alone_before_the_rest():
    """
    The primer plugin must complete before any other plugin starts.

    Plugins execute on worker threads, so the fake below holds each call open
    long enough for genuine overlap to be observable; a fake that returned
    immediately would never catch the race.
    """

    service = InvestigationService()

    lock = threading.Lock()
    live: set[str] = set()
    overlapped_primer = False
    peak_concurrency = 0
    started_order: list[str] = []

    def fake_execute_plugin(memory_dump: Path, plugin_name: str):
        nonlocal overlapped_primer, peak_concurrency

        with lock:
            started_order.append(plugin_name)
            live.add(plugin_name)
            peak_concurrency = max(peak_concurrency, len(live))
            # Anything running alongside the primer is exactly the condition
            # that corrupts Volatility's symbol cache on Windows.
            if "windows.info" in live and len(live) > 1:
                overlapped_primer = True

        # Hold the "process" open so concurrency is real, not theoretical.
        time.sleep(0.05)

        with lock:
            live.discard(plugin_name)

        return ExecutionResult(plugin=plugin_name)

    service.execute_plugin = fake_execute_plugin  # type: ignore[assignment]

    plugins = [
        "windows.info",
        "windows.pslist",
        "windows.pstree",
        "windows.netscan",
        "windows.malfind",
    ]

    results = await service.run_investigation_async(
        memory_dump=Path("/tmp/dump.raw"),
        plugins=plugins,
        max_concurrency=4,
    )

    assert len(results) == len(plugins)

    # The primer ran first and nothing overlapped it.
    assert started_order[0] == "windows.info"
    assert not overlapped_primer, (
        "another plugin ran while the symbol-cache primer was still "
        "executing; this is the WinError 32 race"
    )

    # The remaining plugins still parallelise afterwards.
    assert peak_concurrency > 1, (
        "plugins after the primer should still run concurrently"
    )

    assert sorted(started_order) == sorted(plugins)


@pytest.mark.asyncio
async def test_progress_callbacks_stay_monotonic_with_priming():
    """Priming must not disturb the 0..n-1 progress indexing."""

    service = InvestigationService()

    service.execute_plugin = (  # type: ignore[assignment]
        lambda memory_dump, plugin_name: ExecutionResult(plugin=plugin_name)
    )

    indexes: list[int] = []
    totals: list[int] = []

    def on_completed(index: int, total: int, result, execution_time: float):
        indexes.append(index)
        totals.append(total)

    plugins = ["a", "b", "c", "d"]

    await service.run_investigation_async(
        memory_dump=Path("/tmp/dump.raw"),
        plugins=plugins,
        on_plugin_completed=on_completed,
        max_concurrency=2,
    )

    assert sorted(indexes) == [0, 1, 2, 3]
    assert set(totals) == {4}


@pytest.mark.asyncio
async def test_single_plugin_investigation_still_runs():
    """A one-plugin run must not be broken by the priming split."""

    service = InvestigationService()

    service.execute_plugin = (  # type: ignore[assignment]
        lambda memory_dump, plugin_name: ExecutionResult(plugin=plugin_name)
    )

    results = await service.run_investigation_async(
        memory_dump=Path("/tmp/dump.raw"),
        plugins=["windows.info"],
    )

    assert len(results) == 1
    assert results[0].plugin == "windows.info"


@pytest.mark.asyncio
async def test_empty_plugin_list_returns_no_results():
    """An empty plugin list must not index into plugins[0]."""

    service = InvestigationService()

    results = await service.run_investigation_async(
        memory_dump=Path("/tmp/dump.raw"),
        plugins=[],
    )

    assert results == []


def test_asyncio_available():
    """Guard so the module fails loudly if asyncio import is dropped."""

    assert asyncio is not None
