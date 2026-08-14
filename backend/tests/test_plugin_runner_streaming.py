"""
Tests for Phase 3 (plugin output streaming + parallel execution).

Covers:
- ``volatility_json_parser.parse_file`` reads streamed output from disk and
  matches the in-memory path.
- ``PluginRunner.execute_plugin`` streams stdout/stderr to temporary files
  (never buffers the output in RAM), exposes ``json_output_path`` on success,
  removes temp files on failure/timeout, and honors execution timeouts.
- ``InvestigationService.run_investigation_async`` runs plugins concurrently
  via ``asyncio.to_thread`` with a bounded concurrency limit, invokes the
  callbacks on the event loop with monotonic completion indices, preserves
  result ordering, and never lets a failing plugin abort the run.

The real ``app.volatility.manager`` module is replaced in ``sys.modules``
(following the repo's established stub pattern) so the Volatility stack can
be imported without a ``vol`` binary on PATH; ``subprocess.Popen`` is faked.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import subprocess
import sys
import threading
import time
import types

import pytest


class _FakeVolatilityManager:
    executable = "vol-fake"


# The stub must be installed BEFORE any import that pulls in the Volatility
# stack (``app.services.investigation_service`` -> execution_engine ->
# plugin_runner -> manager), otherwise VolatilityManager() raises at import.
_fake_manager = types.ModuleType("app.volatility.manager")
_fake_manager.volatility_manager = _FakeVolatilityManager()
sys.modules["app.volatility.manager"] = _fake_manager


def _load_real_investigation_service_module():
    """Load the real investigation_service module despite any test stub.

    Other test modules replace ``app.services.investigation_service`` in
    ``sys.modules`` with a lightweight stub that lacks ``InvestigationService``.
    This temporarily evicts the stub to import the real module (safe because
    the Volatility manager is already stubbed), then restores the stub so
    those modules keep their shared object during the run phase.
    """

    existing = sys.modules.get("app.services.investigation_service")

    if existing is not None and hasattr(existing, "InvestigationService"):
        return existing

    restored: list[tuple[str, object]] = []

    if existing is not None:
        del sys.modules["app.services.investigation_service"]
        restored.append(("app.services.investigation_service", existing))

    try:
        return importlib.import_module("app.services.investigation_service")
    finally:
        for name, module in restored:
            sys.modules[name] = module


from app.parsers.volatility_json_parser import (  # noqa: E402
    volatility_json_parser,
)
from app.volatility import plugin_runner as plugin_runner_module  # noqa: E402
from app.volatility.execution_engine import ExecutionResult  # noqa: E402

InvestigationService = (
    _load_real_investigation_service_module().InvestigationService
)  # noqa: E402

from app.volatility.plugin_runner import (  # noqa: E402
    PluginExecutionResult,
    PluginRunner,
)


# ==============================================================================
# Fake Popen
# ==============================================================================


class _FakePopen:
    """Writes canned stdout/stderr into the file handles, then waits."""

    _SIDE_EFFECTS: dict[str, object] = {
        "stdout": b'[{"A": 1}, {"B": 2}]',
        "stderr": "",
        "returncode": 0,
        "timeout": None,
        "ctor_error": None,
    }

    def __init__(self, command, stdout=None, stderr=None, **kwargs):
        self.command = command
        self._stdout = self._SIDE_EFFECTS.get("stdout")
        self._stderr_text = self._SIDE_EFFECTS.get("stderr", "")
        self._timeout_error = self._SIDE_EFFECTS.get("timeout")
        self._raise_ctor = self._SIDE_EFFECTS.get("ctor_error")
        self.returncode = self._SIDE_EFFECTS.get("returncode", 0)

        if stdout is not None:
            stdout.write(self._stdout if self._stdout is not None else b'"[]"')
            stdout.flush()
        if stderr is not None:
            stderr.write(str(self._stderr_text).encode("utf-8"))
            stderr.flush()

        if self._raise_ctor is not None:
            raise self._raise_ctor

    def wait(self, timeout=None):
        if self._timeout_error is not None and not getattr(self, "_raised", False):
            self._raised = True
            raise self._timeout_error
        return self.returncode

    def kill(self):
        self.returncode = -9


@pytest.fixture()
def fake_popen(monkeypatch):
    _FakePopen._SIDE_EFFECTS = {
        "stdout": b'[{"A": 1}, {"B": 2}]',
        "stderr": "",
        "returncode": 0,
        "timeout": None,
        "ctor_error": None,
    }

    monkeypatch.setattr(
        plugin_runner_module.subprocess,
        "Popen",
        _FakePopen,
    )


@pytest.fixture()
def runner(tmp_path, monkeypatch):
    instance = PluginRunner.__new__(PluginRunner)
    instance._manager = _FakeVolatilityManager()
    instance._registry = plugin_runner_module.plugin_registry
    instance._temp_directory = tmp_path
    return instance


def _assert_only(path, names):
    remaining = sorted(p.name for p in path.iterdir())
    assert remaining == names


# ==============================================================================
# Parser: parse_file
# ==============================================================================


def test_parse_file_matches_in_memory_parse(tmp_path):
    plugin = "windows.pslist"
    rows = [
        {"pid": 1, "name": "a.exe"},
        {"pid": 2, "name": "b.exe"},
    ]

    output_path = tmp_path / "pslist.out"
    output_path.write_text(json.dumps(rows), encoding="utf-8")

    from_file = volatility_json_parser.parse_file(plugin, output_path)
    from_string = volatility_json_parser.parse(plugin, json.dumps(rows))

    assert from_file.plugin == plugin
    assert from_file.row_count == from_string.row_count
    assert from_file.rows == from_string.rows


def test_parse_file_raises_for_missing_file(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        volatility_json_parser.parse_file(
            "windows.info",
            tmp_path / "missing.out",
        )


def test_parse_file_raises_for_invalid_json(tmp_path):
    output_path = tmp_path / "bad.out"
    output_path.write_text("{not json", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid Volatility JSON"):
        volatility_json_parser.parse_file("windows.info", output_path)


# ==============================================================================
# PluginRunner: streaming to disk
# ==============================================================================


def test_execute_streams_stdout_and_exposes_path(
    runner,
    tmp_path,
    fake_popen,
):
    result: PluginExecutionResult = runner.execute_plugin(
        memory_dump=tmp_path / "dump.mem",
        plugin_name="windows.pslist",
    )

    assert result.success is True
    assert result.return_code == 0
    assert result.stdout == ""
    assert result.error_message is None

    assert result.json_output is None
    assert result.json_output_path is not None
    assert result.json_output_path.exists()

    assert result.json_output_path.read_text(
        encoding="utf-8"
    ) == '[{"A": 1}, {"B": 2}]'

    assert result.command[0] == "vol-fake"

    # The JSON remains on disk for the caller; the stderr temp was removed.
    remaining = sorted(p.name for p in tmp_path.iterdir())
    assert len(remaining) == 1
    assert result.json_output_path.name in remaining


def test_execute_cleans_up_temp_files_on_failure(
    runner,
    tmp_path,
    fake_popen,
):
    _FakePopen._SIDE_EFFECTS = {
        "stdout": b'"bogus"',
        "stderr": "plugin exploded: bad",
        "returncode": 1,
        "timeout": None,
        "ctor_error": None,
    }

    result: PluginExecutionResult = runner.execute_plugin(
        memory_dump=tmp_path / "dump.mem",
        plugin_name="windows.pslist",
    )

    assert result.success is False
    assert result.return_code == 1
    assert "plugin exploded" in result.error_message
    assert result.json_output is None
    assert result.json_output_path is None

    _assert_only(tmp_path, [])


def test_execute_handles_timeout_and_kills(
    runner,
    tmp_path,
    fake_popen,
):
    _FakePopen._SIDE_EFFECTS = {
        "stdout": b"[]",
        "stderr": "slow",
        "returncode": 0,
        "timeout": subprocess.TimeoutExpired("vol-fake", 1),
        "ctor_error": None,
    }

    result: PluginExecutionResult = runner.execute_plugin(
        memory_dump=tmp_path / "dump.mem",
        plugin_name="windows.pslist",
        timeout=1,
    )

    assert result.success is False
    assert result.return_code == -1
    assert result.error_message == "Execution timed out."

    _assert_only(tmp_path, [])


def test_execute_reports_spawn_errors(
    runner,
    tmp_path,
    fake_popen,
):
    _FakePopen._SIDE_EFFECTS = {
        "stdout": None,
        "stderr": "",
        "returncode": 0,
        "timeout": None,
        "ctor_error": RuntimeError("no vol"),
    }

    result: PluginExecutionResult = runner.execute_plugin(
        memory_dump=tmp_path / "dump.mem",
        plugin_name="windows.pslist",
    )

    assert result.success is False
    assert result.return_code == -1
    assert "no vol" in result.error_message

    _assert_only(tmp_path, [])


# ==============================================================================
# InvestigationService.run_investigation_async
# ==============================================================================


class _StubInvestigationService(InvestigationService):
    """Executes plugins with a tiny sleep and records concurrency."""

    def __init__(self, delay: float = 0.02) -> None:
        self._delay = delay
        self._active = 0
        self.max_active = 0

    def execute_plugin(self, memory_dump, plugin_name):
        self._active += 1
        self.max_active = max(self.max_active, self._active)
        time.sleep(self._delay)
        self._active -= 1
        return ExecutionResult(
            plugin=plugin_name,
            success=True,
            return_code=0,
            stdout="",
            stderr="",
        )


def test_run_investigation_async_orders_results_and_callbacks():
    service = _StubInvestigationService(delay=0.02)

    main_thread_id = threading.get_ident()
    started: list[str] = []
    completed: list[tuple[int, int, str]] = []
    callback_threads: set[int] = set()

    def on_plugin_started(plugin: str) -> None:
        started.append(plugin)
        callback_threads.add(threading.get_ident())

    def on_plugin_completed(index, total, result, duration) -> None:
        completed.append((index, total, result.plugin))
        callback_threads.add(threading.get_ident())

    async def scenario():
        return await service.run_investigation_async(
            memory_dump="dump.mem",
            plugins=["p1", "p2", "p3", "p4", "p5", "p6"],
            on_plugin_started=on_plugin_started,
            on_plugin_completed=on_plugin_completed,
            max_concurrency=2,
        )

    results = asyncio.run(scenario())

    assert [r.plugin for r in results] == ["p1", "p2", "p3", "p4", "p5", "p6"]
    assert all(r.success for r in results)

    assert len(started) == 6
    assert len(completed) == 6

    # Completion indices are monotonic (progress stays correct under
    # concurrency) and cover every plugin exactly once.
    indices = [entry[0] for entry in completed]
    assert indices == sorted(indices)
    assert set(entry[2] for entry in completed) == {
        "p1", "p2", "p3", "p4", "p5", "p6",
    }
    for index, total, _plugin in completed:
        assert index < total
        assert total == 6

    # Callbacks ran on the event loop thread, never on a worker thread.
    assert callback_threads == {main_thread_id}


def test_run_investigation_async_respects_concurrency_limit():
    service = _StubInvestigationService(delay=0.02)

    async def scenario():
        await service.run_investigation_async(
            memory_dump="dump.mem",
            plugins=[f"p{i}" for i in range(6)],
            max_concurrency=2,
        )
        return service.max_active

    max_active = asyncio.run(scenario())

    assert max_active == 2


def test_run_investigation_async_swallows_plugin_failures():
    service = _StubInvestigationService(delay=0.0)

    def _explode(memory_dump, plugin_name):
        if plugin_name == "p3":
            raise RuntimeError("boom")
        return ExecutionResult(
            plugin=plugin_name,
            success=True,
            return_code=0,
            stdout="",
            stderr="",
        )

    service.execute_plugin = _explode

    async def scenario():
        return await service.run_investigation_async(
            memory_dump="dump.mem",
            plugins=["p1", "p2", "p3", "p4"],
        )

    results = asyncio.run(scenario())

    assert [r.plugin for r in results] == ["p1", "p2", "p3", "p4"]
    assert results[2].success is False
    assert "boom" in results[2].stderr
    assert all(r.success for r in results if r.plugin != "p3")


def test_run_investigation_async_empty_plugins():
    service = _StubInvestigationService(delay=0.0)

    async def scenario():
        return await service.run_investigation_async(
            memory_dump="dump.mem",
            plugins=[],
        )

    assert asyncio.run(scenario()) == []