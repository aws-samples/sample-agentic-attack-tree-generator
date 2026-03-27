"""Run manager for ThreatForest pipeline executions.

Bridges the web UI to the ThreatForest orchestrator by managing run lifecycle,
spawning background threads for pipeline execution, and routing progress events
to asyncio queues that WebSocket handlers consume.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from server.models import RunConfig, RunState
from server.scan_control import ScanControl

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Progress event helpers
# ---------------------------------------------------------------------------

class ProgressEvent:
    """Lightweight progress event pushed through the queue to WebSocket clients."""

    def __init__(
        self,
        *,
        event_type: str,
        stage: str,
        percentage: float,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.event_type = event_type
        self.stage = stage
        self.percentage = percentage
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.event_type,
            "stage": self.stage,
            "percentage": self.percentage,
            "message": self.message,
            "details": self.details,
            "server_ts": time.time() * 1000,  # epoch ms for client-side timing
        }


# ---------------------------------------------------------------------------
# Orchestrator protocol — pluggable so the real engine is optional
# ---------------------------------------------------------------------------

class OrchestratorExecutor(Protocol):
    """Protocol for executing a ThreatForest pipeline run.

    Implementations receive the run configuration, a progress callback, and an
    optional ``ScanControl``.  They should return a dict on normal completion or
    when interrupted.  The dict always contains ``"status"`` (``"complete"``,
    ``"pause"``, or ``"stop"``); a normal completion also includes
    ``"output_dir"`` and ``"app_id"``.
    """

    def __call__(
        self,
        config: RunConfig,
        progress_callback: Callable[[ProgressEvent], None],
        scan_control: Any | None = None,
    ) -> dict[str, str]:
        ...


# ---------------------------------------------------------------------------
# RunManager
# ---------------------------------------------------------------------------

class RunManager:
    """Manages ThreatForest pipeline runs and their progress event queues.

    Each run gets a unique ID, an ``asyncio.Queue`` for streaming progress
    events to WebSocket clients, a ``ScanControl`` for pause/stop signalling,
    and a background thread that drives the orchestrator.
    """

    def __init__(self, executor: OrchestratorExecutor | None = None) -> None:
        self.active_runs: dict[str, RunState] = {}
        self._queues: dict[str, asyncio.Queue[dict[str, Any]]] = {}
        self._loops: dict[str, asyncio.AbstractEventLoop] = {}
        self._controls: dict[str, ScanControl] = {}
        self._executor = executor

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start_run(self, config: RunConfig) -> str:
        """Validate config, create a new run, and spawn the orchestrator.

        Returns the generated ``run_id``.

        Raises
        ------
        FileNotFoundError
            If ``config.project_path`` does not exist.
        NotADirectoryError
            If ``config.project_path`` exists but is not a directory.
        RuntimeError
            If no orchestrator executor has been configured.
        """
        project = Path(config.project_path)
        if not project.is_absolute():
            # Resolve relative paths against the repo root (src/../..)
            _repo_root = Path(__file__).resolve().parent.parent.parent
            project = _repo_root / project
        if not project.exists():
            raise FileNotFoundError(
                f"Project path does not exist: {config.project_path}"
            )
        if not project.is_dir():
            raise NotADirectoryError(
                f"Project path is not a directory: {config.project_path}"
            )

        if self._executor is None:
            raise RuntimeError(
                "No orchestrator executor configured. "
                "Provide one via RunManager(executor=...)."
            )

        run_id = uuid.uuid4().hex
        now = datetime.now(tz=timezone.utc).isoformat()

        state = RunState(
            run_id=run_id,
            status="pending",
            config=config,
            started_at=now,
        )
        self.active_runs[run_id] = state

        # Create the asyncio queue and capture the current event loop
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._queues[run_id] = queue

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        self._loops[run_id] = loop  # type: ignore[assignment]

        # Create a ScanControl for this run
        control = ScanControl()
        self._controls[run_id] = control

        # Spawn background thread
        thread = threading.Thread(
            target=self._execute_in_thread,
            args=(run_id, config),
            daemon=True,
        )
        thread.start()

        return run_id

    def get_progress_queue(self, run_id: str) -> asyncio.Queue[dict[str, Any]]:
        """Return the event queue for *run_id*.

        Raises
        ------
        KeyError
            If *run_id* is not known.
        """
        try:
            return self._queues[run_id]
        except KeyError:
            raise KeyError(f"Unknown run_id: {run_id}") from None

    def pause_run(self, run_id: str) -> None:
        """Request the executor to pause after the current stage completes.

        Raises
        ------
        KeyError
            If *run_id* is not known.
        RuntimeError
            If the run is not in a pausable state.
        """
        state = self.active_runs.get(run_id)
        if state is None:
            raise KeyError(f"Unknown run_id: {run_id}")
        if state.status not in ("pending", "running"):
            raise RuntimeError(
                f"Run {run_id} cannot be paused (current status: {state.status})"
            )
        control = self._controls.get(run_id)
        if control is None:
            raise RuntimeError(f"No control object for run {run_id}")
        control.request_pause()

    def stop_run(self, run_id: str) -> None:
        """Request the executor to stop after the current stage completes.

        If the run is already paused (executor has exited) this simply updates
        the RunState status to ``"stopped"`` without needing to signal anything.

        Raises
        ------
        KeyError
            If *run_id* is not known.
        RuntimeError
            If the run is in a terminal state and cannot be stopped.
        """
        state = self.active_runs.get(run_id)
        if state is None:
            raise KeyError(f"Unknown run_id: {run_id}")

        if state.status == "paused":
            # Executor thread has already exited; just flip the status.
            state.status = "stopped"
            state.completed_at = datetime.now(tz=timezone.utc).isoformat()
            return

        if state.status not in ("pending", "running"):
            raise RuntimeError(
                f"Run {run_id} cannot be stopped (current status: {state.status})"
            )
        control = self._controls.get(run_id)
        if control is None:
            raise RuntimeError(f"No control object for run {run_id}")
        control.request_stop()

    def resume_run(self, run_id: str) -> str:
        """Create a new run that resumes from the last completed stage.

        Reads ``pause_state.json`` written by the executor when it was paused
        or stopped, rebuilds a ``RunConfig`` that skips already-completed nodes,
        and starts a fresh run that reuses the same run directory (so state
        files are available).

        Returns the new ``run_id``.

        Raises
        ------
        KeyError
            If *run_id* is not known.
        RuntimeError
            If the run has no pause state or is in a non-resumable status.
        """
        state = self.active_runs.get(run_id)
        if state is None:
            raise KeyError(f"Unknown run_id: {run_id}")

        if state.status not in ("paused", "stopped"):
            raise RuntimeError(
                f"Run {run_id} cannot be resumed (current status: {state.status})"
            )

        # Locate the run directory via ScanControl (set by executor on startup)
        control = self._controls.get(run_id)
        run_dir_str = control.run_dir if control else None
        if not run_dir_str:
            raise RuntimeError(
                f"Run directory not found for run {run_id}. "
                "The server may have restarted — please start a new run."
            )

        pause_file = Path(run_dir_str) / "pause_state.json"
        if not pause_file.is_file():
            raise RuntimeError(
                f"No pause_state.json found in {run_dir_str}. "
                "Cannot resume this run."
            )

        pause_data = json.loads(pause_file.read_text(encoding="utf-8"))
        config_data = pause_data.get("config", {})
        completed_nodes: list[str] = pause_data.get("completed_nodes", [])

        new_config = RunConfig(
            project_path=config_data.get("project_path", state.config.project_path),
            threat_source=config_data.get("threat_source", state.config.threat_source),
            threat_file_path=config_data.get("threat_file_path", state.config.threat_file_path),
            # Tell the executor to reuse the existing run directory
            resume_run_dir=run_dir_str,
            # Tell the graph to skip nodes whose outputs are already on disk
            skip_nodes=completed_nodes,
        )

        return self.start_run(new_config)

    def cleanup_run(self, run_id: str) -> None:
        """Remove the event queue and loop reference for a finished run.

        Called by the WebSocket handler after the connection closes to
        prevent memory leaks.  The ``active_runs`` entry is kept so that
        the dashboard endpoint can still serve results.  The ScanControl
        is kept so that ``resume_run`` can locate the run directory.
        """
        self._queues.pop(run_id, None)
        self._loops.pop(run_id, None)

    # ------------------------------------------------------------------
    # Background execution
    # ------------------------------------------------------------------

    def _execute_in_thread(self, run_id: str, config: RunConfig) -> None:
        """Run the orchestrator in a background thread.

        Progress events are pushed to the asyncio queue so that the
        WebSocket handler can forward them to the client.
        """
        state = self.active_runs[run_id]
        state.status = "running"
        queue = self._queues[run_id]
        loop = self._loops.get(run_id)
        control = self._controls.get(run_id)

        def _push_event(event: ProgressEvent) -> None:
            """Thread-safe helper to enqueue a progress event."""
            payload = event.to_dict()
            if loop is not None and loop.is_running():
                loop.call_soon_threadsafe(queue.put_nowait, payload)
            else:
                queue.put_nowait(payload)

        try:
            assert self._executor is not None
            result = self._executor(config, _push_event, scan_control=control)

            result_status = result.get("status", "complete")

            if result_status == "pause":
                state.status = "paused"
                state.paused_at_stage = result.get("paused_at_stage")
                state.paused_at = datetime.now(tz=timezone.utc).isoformat()
                state.completed_at = state.paused_at
                # The executor already pushed a "scan_paused" WebSocket event.

            elif result_status == "stop":
                state.status = "stopped"
                state.paused_at_stage = result.get("paused_at_stage")
                state.completed_at = datetime.now(tz=timezone.utc).isoformat()
                # The executor already pushed a "scan_stopped" WebSocket event.

            else:
                # Normal completion
                state.status = "complete"
                state.completed_at = datetime.now(tz=timezone.utc).isoformat()
                state.output_dir = result.get("output_dir")

                _push_event(ProgressEvent(
                    event_type="stage_complete",
                    stage="complete",
                    percentage=100,
                    message="Pipeline completed successfully",
                    details={
                        "output_dir": state.output_dir,
                        "app_id": result.get("app_id", ""),
                    },
                ))

        except Exception as exc:
            logger.exception("Run %s failed", run_id)
            state.status = "failed"
            state.completed_at = datetime.now(tz=timezone.utc).isoformat()
            state.error = str(exc)

            stage_name = getattr(exc, "stage", "unknown")
            _push_event(ProgressEvent(
                event_type="error",
                stage=stage_name,
                percentage=state_percentage(state),
                message=f"Pipeline failed: {exc}",
                details={"error": str(exc), "stage": stage_name},
            ))


def state_percentage(state: RunState) -> float:
    """Derive a rough percentage from the current run state."""
    if state.status == "complete":
        return 100.0
    if state.status == "failed":
        return 0.0
    return 0.0
