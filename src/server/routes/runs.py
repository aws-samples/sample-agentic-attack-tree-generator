"""Run initiation and WebSocket progress streaming routes."""

from __future__ import annotations

import asyncio
import logging
import time

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from server.models import RunConfig, RunResponse
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


@router.post("/runs", response_model=RunResponse, status_code=202)
async def create_run(config: RunConfig) -> RunResponse:
    """Initiate a new ThreatForest pipeline run.

    Validates the project path, delegates to RunManager, and returns
    a 202 with the generated run_id.

    - **400** if the project path does not exist or is not a directory
    - **500** if no orchestrator executor is configured
    """
    manager = get_run_manager()
    try:
        run_id = manager.start_run(config)
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return RunResponse(run_id=run_id)


@ws_router.websocket("/ws/runs/{run_id}")
async def run_progress(websocket: WebSocket, run_id: str) -> None:
    """Stream pipeline progress events over WebSocket.

    Reads ProgressEvent dicts from the RunManager queue and sends them
    as JSON to the connected client.  When the queue is idle for longer
    than ``WS_HEARTBEAT_INTERVAL`` seconds a lightweight heartbeat
    message is sent to keep the connection alive through proxies and
    browsers that close idle WebSocket connections.

    Closes the connection after the completion or error event.
    Closes with code 4004 if the run_id is unknown.
    """
    manager = get_run_manager()

    try:
        queue = manager.get_progress_queue(run_id)
    except KeyError:
        await websocket.accept()
        await websocket.close(code=4004, reason=f"Unknown run_id: {run_id}")
        return

    await websocket.accept()

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
            if event_type in ("stage_complete", "error"):
                stage = event.get("stage", "")
                if event_type == "error" or stage == "complete":
                    break
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected for run %s", run_id)
    except Exception:
        logger.exception("WebSocket error for run %s", run_id)
    finally:
        # Clean up the run's queue and event-loop reference to prevent
        # memory leaks for long-running server instances.
        manager.cleanup_run(run_id)
