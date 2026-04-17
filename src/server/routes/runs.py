"""Run initiation, control, and WebSocket progress streaming routes."""

from __future__ import annotations

import asyncio
import logging
import time

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from server.applications import ApplicationNotFoundError
from server.models import InteractionResponse, ResumeResponse, RunConfig, RunResponse, RunState
from server.routes.applications import get_app_repository
from server.run_manager import RunManager

# Heartbeat interval in seconds — keeps idle WebSocket connections alive
# through proxies and browsers that close idle connections after 30-60s.
WS_HEARTBEAT_INTERVAL = 15.0

logger = logging.getLogger(__name__)

# REST router — mounted under /api
router = APIRouter()

# WebSocket router — mounted at root (no /api prefix)
ws_router = APIRouter()

# Module-level RunManager — swappable for testing
_run_manager = RunManager()


def get_run_manager() -> RunManager:
    """Return the module-level RunManager instance."""
    return _run_manager


def set_run_manager(manager: RunManager) -> None:
    """Replace the module-level RunManager (useful for testing)."""
    global _run_manager
    _run_manager = manager


@router.get("/runs", status_code=200)
async def list_runs(status: str | None = None) -> dict:
    """List all known runs, optionally filtered by status.

    Query parameters:
    - **status** — comma-separated statuses to include (e.g. ``running,pending``)

    Returns ``{ runs: RunState[] }``.
    """
    manager = get_run_manager()
    runs = list(manager.active_runs.values())
    if status:
        allowed = {s.strip() for s in status.split(",")}
        runs = [r for r in runs if r.status in allowed]
    # Most recent first
    runs.sort(key=lambda r: r.started_at, reverse=True)
    return {"runs": runs}


@router.post("/runs", response_model=RunResponse, status_code=202)
async def create_run(config: RunConfig) -> RunResponse:
    """Initiate a new ThreatForest pipeline run.

    In the v2 UX model, new runs must reference an existing ``Application``
    via ``app_id``; the route resolves the stored ``project_path`` so the UI
    never has to re-send it. Resume flows (``resume_run_dir`` set) skip the
    lookup because they reconstruct the config from ``pause_state.json``.

    - **400** if ``app_id`` is missing for a fresh run, or the project path
      does not exist / is not a directory
    - **404** if ``app_id`` does not resolve to a known application
    - **500** if no orchestrator executor is configured
    """
    if config.resume_run_dir is None:
        if config.app_id is None:
            raise HTTPException(
                status_code=400,
                detail="app_id is required to start a new run",
            )
        try:
            app = get_app_repository().get_application(config.app_id)
        except ApplicationNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        # Authoritative source of truth for the scan target — override whatever
        # the client sent (UI should send the same value, but we prefer the
        # stored path if they drift).
        config = config.model_copy(update={"project_path": app.project_path})

    manager = get_run_manager()
    try:
        run_id = manager.start_run(config)
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return RunResponse(run_id=run_id)


@router.get("/runs/{run_id}", response_model=RunState)
async def get_run(run_id: str) -> RunState:
    """Return the current state of a run.

    - **404** if *run_id* is not known
    """
    manager = get_run_manager()
    state = manager.active_runs.get(run_id)
    if state is None:
        raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")
    return state


@router.post("/runs/{run_id}/pause", status_code=200)
async def pause_run(run_id: str) -> dict:
    """Request the pipeline to pause after the current stage completes.

    The run transitions to ``"paused"`` once the executor acknowledges the
    request (signalled by a ``scan_paused`` WebSocket event).

    - **404** if *run_id* is not known
    - **400** if the run is not in a pausable state
    """
    manager = get_run_manager()
    try:
        manager.pause_run(run_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"status": "pause_requested"}


@router.post("/runs/{run_id}/stop", status_code=200)
async def stop_run(run_id: str) -> dict:
    """Request the pipeline to stop after the current stage completes.

    If the run is already paused (executor has exited) the status is flipped
    to ``"stopped"`` immediately without waiting for a WebSocket event.

    - **404** if *run_id* is not known
    - **400** if the run is in a terminal state
    """
    manager = get_run_manager()
    try:
        manager.stop_run(run_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"status": "stop_requested"}


@router.post("/runs/{run_id}/resume", response_model=ResumeResponse, status_code=202)
async def resume_run(run_id: str) -> ResumeResponse:
    """Resume a paused or stopped run.

    Reads ``pause_state.json`` from the original run directory, constructs a
    new ``RunConfig`` that skips already-completed graph nodes, and starts a
    new run in the same directory.  Returns the new ``run_id``; clients should
    navigate to ``/runs/<new_run_id>/progress``.

    - **404** if *run_id* is not known
    - **400** if the run cannot be resumed (wrong status or missing state file)
    """
    manager = get_run_manager()
    try:
        # resume_run may block waiting for a "pausing" run to finish its
        # current stage, so run it off the event loop.
        new_run_id = await asyncio.to_thread(manager.resume_run, run_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except (RuntimeError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return ResumeResponse(new_run_id=new_run_id)


@router.post("/runs/{run_id}/respond", status_code=200)
async def submit_run_response(run_id: str, body: InteractionResponse) -> dict:
    """Submit a user response to an interviewer question.

    The interviewer agent pauses and sends an ``awaiting_input`` WebSocket
    event when it needs user input.  This endpoint delivers the user's
    answer back to the blocked agent thread.

    - **404** if *run_id* is not known or has no pending interaction
    """
    manager = get_run_manager()
    try:
        manager.submit_interaction_response(run_id, body.text)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"ok": True}


@ws_router.websocket("/ws/runs/{run_id}")
async def run_progress(websocket: WebSocket, run_id: str) -> None:
    """Stream pipeline progress events over WebSocket.

    Reads ProgressEvent dicts from the RunManager queue and sends them
    as JSON to the connected client.  When the queue is idle for longer
    than ``WS_HEARTBEAT_INTERVAL`` seconds a lightweight heartbeat
    message is sent to keep the connection alive through proxies and
    browsers that close idle WebSocket connections.

    Closes the connection after completion, error, pause, or stop events.
    Closes with code 4004 if the run_id is unknown.
    """
    manager = get_run_manager()

    try:
        queue = manager.get_progress_queue(run_id)
    except KeyError:
        # Queue was cleaned up but run may have history (completed/failed run)
        history = manager.get_event_history(run_id)
        if not history:
            await websocket.accept()
            await websocket.close(code=4004, reason=f"Unknown run_id: {run_id}")
            return
        # Replay history for a terminal run that already had its queue removed
        await websocket.accept()
        for event in history:
            await websocket.send_json(event)
        await websocket.close(code=1000, reason="Run is in terminal state")
        return

    await websocket.accept()

    # Replay event history for reconnecting clients
    history = manager.get_event_history(run_id)
    for event in history:
        await websocket.send_json(event)

    # If the run already reached a terminal state, close cleanly with 1000
    # so the client's reconnect logic does not kick in.
    if history:
        last = history[-1]
        last_type = last.get("type", "")
        last_stage = last.get("stage", "")
        if last_type in ("error", "scan_paused", "scan_stopped") or (
            last_type == "stage_complete" and last_stage == "complete"
        ):
            await websocket.close(code=1000, reason="Run is in terminal state")
            return

    try:
        while True:
            try:
                event = await asyncio.wait_for(
                    queue.get(), timeout=WS_HEARTBEAT_INTERVAL
                )
            except asyncio.TimeoutError:
                # No event within the heartbeat window — send a keepalive
                await websocket.send_json({
                    "type": "heartbeat",
                    "timestamp": time.time(),
                })
                continue

            await websocket.send_json(event)

            # Close after terminal events
            event_type = event.get("type", "")
            if event_type in ("stage_complete", "error", "scan_paused", "scan_stopped"):
                stage = event.get("stage", "")
                if event_type in ("error", "scan_paused", "scan_stopped") or stage == "complete":
                    break
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected for run %s", run_id)
    except Exception:
        logger.exception("WebSocket error for run %s", run_id)
    finally:
        manager.cleanup_run(run_id)
