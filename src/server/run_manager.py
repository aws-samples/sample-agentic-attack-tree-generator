"""Run manager for ThreatForest pipeline executions.

Bridges the web UI to the ThreatForest orchestrator by managing run lifecycle,
spawning background threads for pipeline execution, and routing progress events
to asyncio queues that WebSocket handlers consume.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from server.models import RunConfig, RunState

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

    Implementations receive the run configuration and a callback that should
    be invoked with ``ProgressEvent`` instances as the pipeline progresses.

    Must return a dict with ``output_dir`` and ``dashboard_path`` on success,
    or raise an exception on failure.
    """

    def __call__(
        self,
        config: RunConfig,
        progress_callback: Callable[[ProgressEvent], None],
    ) -> dict[str, str]:
        ...


# ---------------------------------------------------------------------------
# RunManager
# ---------------------------------------------------------------------------

class RunManager:
    """Manages ThreatForest pipeline runs and their progress event queues.

    Each run gets a unique ID, an ``asyncio.Queue`` for streaming progress
    events to WebSocket clients, and a background thread that drives the
    orchestrator.
    """

    def __init__(self, executor: OrchestratorExecutor | None = None) -> None:
        self.active_runs: dict[str, RunState] = {}
        self._queues: dict[str, asyncio.Queue[dict[str, Any]]] = {}
        self._loops: dict[str, asyncio.AbstractEventLoop] = {}
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

    def cleanup_run(self, run_id: str) -> None:
        """Remove the event queue and loop reference for a finished run.

        Called by the WebSocket handler after the connection closes to
        prevent memory leaks.  The ``active_runs`` entry is kept so that
        the dashboard endpoint can still serve results.
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

        def _push_event(event: ProgressEvent) -> None:
            """Thread-safe helper to enqueue a progress event."""
            payload = event.to_dict()
            if loop is not None and loop.is_running():
                loop.call_soon_threadsafe(queue.put_nowait, payload)
            else:
                queue.put_nowait(payload)

        try:
            assert self._executor is not None
            result = self._executor(config, _push_event)

            # Mark success
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
            # Persist traceback to file for debugging
            import traceback as _tb
            _err_file = Path(f".threatforest/run_error_{run_id}.log")
            try:
                _err_file.write_text(_tb.format_exc(), encoding="utf-8")
                logger.info("Error details written to %s", _err_file)
            except OSError:
                pass
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
