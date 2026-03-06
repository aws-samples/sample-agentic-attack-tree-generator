"""Unit tests for the runs API and WebSocket endpoints."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable

import pytest
from fastapi.testclient import TestClient

from server.app import app
from server.models import RunConfig
from server.run_manager import ProgressEvent, RunManager
from server.routes.runs import set_run_manager


def _noop_executor(
    config: RunConfig,
    progress_callback: Callable[[ProgressEvent], None],
) -> dict[str, str]:
    """Executor that immediately completes with dummy paths."""
    progress_callback(ProgressEvent(
        event_type="stage_complete",
        stage="repo_analysis",
        percentage=16,
        message="Repository analysis complete",
    ))
    return {
        "output_dir": "/tmp/output",
        "dashboard_path": "/tmp/output/dashboard.html",
    }


def _failing_executor(
    config: RunConfig,
    progress_callback: Callable[[ProgressEvent], None],
) -> dict[str, str]:
    """Executor that raises an exception."""
    exc = RuntimeError("Stage failed")
    exc.stage = "threat_parsing"  # type: ignore[attr-defined]
    raise exc


@pytest.fixture()
def project_dir(tmp_path: Path) -> Path:
    """Create a temporary project directory."""
    d = tmp_path / "my-project"
    d.mkdir()
    return d


@pytest.fixture()
def manager_with_executor(project_dir: Path) -> RunManager:
    """RunManager with a noop executor."""
    return RunManager(executor=_noop_executor)


@pytest.fixture()
def manager_no_executor() -> RunManager:
    """RunManager without an executor."""
    return RunManager(executor=None)


@pytest.fixture()
def manager_failing_executor() -> RunManager:
    """RunManager with a failing executor."""
    return RunManager(executor=_failing_executor)


@pytest.fixture()
def client(manager_with_executor: RunManager):
    """TestClient wired to a RunManager with a working executor."""
    set_run_manager(manager_with_executor)
    yield TestClient(app)


@pytest.fixture()
def client_no_executor(manager_no_executor: RunManager):
    """TestClient wired to a RunManager without an executor."""
    set_run_manager(manager_no_executor)
    yield TestClient(app)


@pytest.fixture()
def client_failing(manager_failing_executor: RunManager):
    """TestClient wired to a RunManager with a failing executor."""
    set_run_manager(manager_failing_executor)
    yield TestClient(app)


# -----------------------------------------------------------------------
# POST /api/runs
# -----------------------------------------------------------------------

class TestCreateRun:
    def test_returns_202_with_run_id(self, client: TestClient, project_dir: Path) -> None:
        resp = client.post("/api/runs", json={
            "project_path": str(project_dir),
            "threat_source": "auto",
        })
        assert resp.status_code == 202
        data = resp.json()
        assert "run_id" in data
        assert isinstance(data["run_id"], str)
        assert len(data["run_id"]) > 0

    def test_400_for_nonexistent_path(self, client: TestClient) -> None:
        resp = client.post("/api/runs", json={
            "project_path": "/nonexistent/path/that/does/not/exist",
            "threat_source": "auto",
        })
        assert resp.status_code == 400
        assert "does not exist" in resp.json()["detail"]

    def test_400_for_file_path(self, client: TestClient, tmp_path: Path) -> None:
        f = tmp_path / "somefile.txt"
        f.write_text("hello")
        resp = client.post("/api/runs", json={
            "project_path": str(f),
            "threat_source": "auto",
        })
        assert resp.status_code == 400
        assert "not a directory" in resp.json()["detail"]

    def test_500_when_no_executor(self, client_no_executor: TestClient, tmp_path: Path) -> None:
        d = tmp_path / "proj"
        d.mkdir()
        resp = client_no_executor.post("/api/runs", json={
            "project_path": str(d),
            "threat_source": "auto",
        })
        assert resp.status_code == 500
        assert "executor" in resp.json()["detail"].lower()

    def test_accepts_file_threat_source(self, client: TestClient, project_dir: Path) -> None:
        resp = client.post("/api/runs", json={
            "project_path": str(project_dir),
            "threat_source": "file",
            "threat_file_path": "/some/threats.json",
        })
        assert resp.status_code == 202

    def test_422_for_missing_required_fields(self, client: TestClient) -> None:
        resp = client.post("/api/runs", json={})
        assert resp.status_code == 422


# -----------------------------------------------------------------------
# WebSocket /ws/runs/{run_id}
# -----------------------------------------------------------------------

class TestRunProgressWebSocket:
    def test_unknown_run_id_closes_with_4004(self, client: TestClient) -> None:
        with client.websocket_connect("/ws/runs/nonexistent") as ws:
            # The server should close the connection with code 4004.
            # TestClient raises WebSocketDisconnect or returns close frame.
            try:
                ws.receive_json()
                # If we get here, the server didn't close — fail
                pytest.fail("Expected WebSocket to close for unknown run_id")
            except Exception:
                pass  # Connection closed as expected

    def test_receives_progress_and_completion_events(
        self, client: TestClient, project_dir: Path
    ) -> None:
        # Start a run first
        resp = client.post("/api/runs", json={
            "project_path": str(project_dir),
            "threat_source": "auto",
        })
        run_id = resp.json()["run_id"]

        # Give the background thread a moment to push events
        import time
        time.sleep(0.3)

        with client.websocket_connect(f"/ws/runs/{run_id}") as ws:
            events: list[dict] = []
            # Read events until the connection closes or we get the completion
            for _ in range(10):  # safety limit
                try:
                    event = ws.receive_json()
                    events.append(event)
                    if event.get("type") == "stage_complete" and event.get("stage") == "complete":
                        break
                except Exception:
                    break

            assert len(events) >= 1
            # Last event should be the completion event
            last = events[-1]
            assert last["type"] == "stage_complete"
            assert last["stage"] == "complete"
            assert last["percentage"] == 100
            assert "dashboard_path" in last.get("details", {})

    def test_receives_error_event(
        self, client_failing: TestClient, project_dir: Path
    ) -> None:
        resp = client_failing.post("/api/runs", json={
            "project_path": str(project_dir),
            "threat_source": "auto",
        })
        run_id = resp.json()["run_id"]

        import time
        time.sleep(0.3)

        with client_failing.websocket_connect(f"/ws/runs/{run_id}") as ws:
            events: list[dict] = []
            for _ in range(10):
                try:
                    event = ws.receive_json()
                    events.append(event)
                    if event.get("type") == "error":
                        break
                except Exception:
                    break

            assert len(events) >= 1
            last = events[-1]
            assert last["type"] == "error"
            assert "failed" in last["message"].lower()
