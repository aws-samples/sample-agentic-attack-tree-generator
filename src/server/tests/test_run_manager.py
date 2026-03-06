"""Unit tests for RunManager."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any, Callable

import pytest

from server.models import RunConfig
from server.run_manager import ProgressEvent, RunManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(project_path: str) -> RunConfig:
    return RunConfig(project_path=project_path, threat_source="auto")


def _noop_executor(
    config: RunConfig,
    progress_callback: Callable[[ProgressEvent], None],
) -> dict[str, str]:
    """Executor that completes immediately with dummy paths."""
    return {
        "output_dir": "/tmp/output",
        "dashboard_path": "/tmp/output/dashboard.html",
    }


def _slow_executor(
    config: RunConfig,
    progress_callback: Callable[[ProgressEvent], None],
) -> dict[str, str]:
    """Executor that emits a couple of progress events before completing."""
    progress_callback(ProgressEvent(
        event_type="stage_progress",
        stage="Repository Analysis",
        percentage=16,
        message="Analysing repository...",
    ))
    time.sleep(0.05)
    progress_callback(ProgressEvent(
        event_type="stage_complete",
        stage="Repository Analysis",
        percentage=33,
        message="Repository analysis complete",
    ))
    return {
        "output_dir": "/tmp/output",
        "dashboard_path": "/tmp/output/dashboard.html",
    }


class _FailingError(Exception):
    def __init__(self, msg: str, stage: str = "unknown") -> None:
        super().__init__(msg)
        self.stage = stage


def _failing_executor(
    config: RunConfig,
    progress_callback: Callable[[ProgressEvent], None],
) -> dict[str, str]:
    """Executor that raises after one progress event."""
    progress_callback(ProgressEvent(
        event_type="stage_progress",
        stage="Threat Parsing",
        percentage=33,
        message="Parsing threats...",
    ))
    raise _FailingError("Model API timeout", stage="Threat Parsing")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def project_dir(tmp_path: Path) -> Path:
    d = tmp_path / "my_project"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# ProgressEvent
# ---------------------------------------------------------------------------


class TestProgressEvent:
    def test_to_dict_contains_all_fields(self) -> None:
        evt = ProgressEvent(
            event_type="stage_progress",
            stage="Threat Parsing",
            percentage=50.0,
            message="Halfway there",
            details={"extra": "info"},
        )
        d = evt.to_dict()
        assert d["type"] == "stage_progress"
        assert d["stage"] == "Threat Parsing"
        assert d["percentage"] == 50.0
        assert d["message"] == "Halfway there"
        assert d["details"] == {"extra": "info"}

    def test_to_dict_defaults_details_to_empty(self) -> None:
        evt = ProgressEvent(
            event_type="stage_complete",
            stage="complete",
            percentage=100,
            message="Done",
        )
        assert evt.to_dict()["details"] == {}


# ---------------------------------------------------------------------------
# start_run — validation
# ---------------------------------------------------------------------------


class TestStartRunValidation:
    def test_rejects_nonexistent_path(self, tmp_path: Path) -> None:
        mgr = RunManager(executor=_noop_executor)
        config = _make_config(str(tmp_path / "nope"))
        with pytest.raises(FileNotFoundError, match="does not exist"):
            mgr.start_run(config)

    def test_rejects_file_path(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_text("hi")
        mgr = RunManager(executor=_noop_executor)
        config = _make_config(str(f))
        with pytest.raises(NotADirectoryError, match="not a directory"):
            mgr.start_run(config)

    def test_rejects_when_no_executor(self, project_dir: Path) -> None:
        mgr = RunManager()  # no executor
        config = _make_config(str(project_dir))
        with pytest.raises(RuntimeError, match="No orchestrator executor"):
            mgr.start_run(config)

    def test_accepts_valid_directory(self, project_dir: Path) -> None:
        mgr = RunManager(executor=_noop_executor)
        config = _make_config(str(project_dir))
        run_id = mgr.start_run(config)
        assert run_id is not None
        assert len(run_id) == 32  # hex UUID without dashes


# ---------------------------------------------------------------------------
# start_run — state tracking
# ---------------------------------------------------------------------------


class TestStartRunState:
    def test_run_state_created(self, project_dir: Path) -> None:
        mgr = RunManager(executor=_noop_executor)
        config = _make_config(str(project_dir))
        run_id = mgr.start_run(config)
        assert run_id in mgr.active_runs
        state = mgr.active_runs[run_id]
        assert state.run_id == run_id
        assert state.config == config
        assert state.started_at is not None

    def test_run_reaches_complete(self, project_dir: Path) -> None:
        mgr = RunManager(executor=_noop_executor)
        config = _make_config(str(project_dir))
        run_id = mgr.start_run(config)
        # Give the background thread time to finish
        time.sleep(0.3)
        state = mgr.active_runs[run_id]
        assert state.status == "complete"
        assert state.output_dir == "/tmp/output"
        assert state.dashboard_path == "/tmp/output/dashboard.html"
        assert state.completed_at is not None

    def test_run_reaches_failed(self, project_dir: Path) -> None:
        mgr = RunManager(executor=_failing_executor)
        config = _make_config(str(project_dir))
        run_id = mgr.start_run(config)
        time.sleep(0.3)
        state = mgr.active_runs[run_id]
        assert state.status == "failed"
        assert "Model API timeout" in state.error
        assert state.completed_at is not None

    def test_unique_run_ids(self, project_dir: Path) -> None:
        mgr = RunManager(executor=_noop_executor)
        config = _make_config(str(project_dir))
        ids = {mgr.start_run(config) for _ in range(5)}
        assert len(ids) == 5


# ---------------------------------------------------------------------------
# get_progress_queue
# ---------------------------------------------------------------------------


class TestGetProgressQueue:
    def test_returns_queue_for_valid_run(self, project_dir: Path) -> None:
        mgr = RunManager(executor=_noop_executor)
        config = _make_config(str(project_dir))
        run_id = mgr.start_run(config)
        q = mgr.get_progress_queue(run_id)
        assert isinstance(q, asyncio.Queue)

    def test_raises_for_unknown_run(self) -> None:
        mgr = RunManager(executor=_noop_executor)
        with pytest.raises(KeyError, match="Unknown run_id"):
            mgr.get_progress_queue("nonexistent")


# ---------------------------------------------------------------------------
# Progress events flow through the queue
# ---------------------------------------------------------------------------


class TestProgressFlow:
    def test_completion_event_in_queue(self, project_dir: Path) -> None:
        mgr = RunManager(executor=_noop_executor)
        config = _make_config(str(project_dir))
        run_id = mgr.start_run(config)
        q = mgr.get_progress_queue(run_id)
        time.sleep(0.3)

        events: list[dict[str, Any]] = []
        while not q.empty():
            events.append(q.get_nowait())

        # At minimum we should get the final completion event
        assert len(events) >= 1
        last = events[-1]
        assert last["type"] == "stage_complete"
        assert last["stage"] == "complete"
        assert last["percentage"] == 100
        assert last["details"]["dashboard_path"] == "/tmp/output/dashboard.html"
        assert last["details"]["output_dir"] == "/tmp/output"

    def test_progress_events_from_slow_executor(self, project_dir: Path) -> None:
        mgr = RunManager(executor=_slow_executor)
        config = _make_config(str(project_dir))
        run_id = mgr.start_run(config)
        q = mgr.get_progress_queue(run_id)
        time.sleep(0.5)

        events: list[dict[str, Any]] = []
        while not q.empty():
            events.append(q.get_nowait())

        # Should have: stage_progress, stage_complete (from executor), then final completion
        assert len(events) >= 3
        assert events[0]["stage"] == "Repository Analysis"
        assert events[-1]["type"] == "stage_complete"
        assert events[-1]["stage"] == "complete"

    def test_error_event_in_queue(self, project_dir: Path) -> None:
        mgr = RunManager(executor=_failing_executor)
        config = _make_config(str(project_dir))
        run_id = mgr.start_run(config)
        q = mgr.get_progress_queue(run_id)
        time.sleep(0.3)

        events: list[dict[str, Any]] = []
        while not q.empty():
            events.append(q.get_nowait())

        # Should have: one progress event, then the error event
        assert len(events) >= 2
        error_evt = events[-1]
        assert error_evt["type"] == "error"
        assert error_evt["stage"] == "Threat Parsing"
        assert "Model API timeout" in error_evt["message"]
        assert error_evt["details"]["error"] == "Model API timeout"
