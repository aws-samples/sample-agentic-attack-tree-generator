"""ScanControl — signals pause and stop requests to the background executor thread."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any


class ScanInterruptedException(BaseException):
    """Raised inside a Strands agent after a tool call when pause/stop is requested.

    Inherits from BaseException (not Exception) so it bypasses Strands' internal
    ``except Exception`` handlers and propagates all the way up to the executor.
    """


class InterruptHookProvider:
    """Strands HookProvider that raises ScanInterruptedException after each tool call.

    Registered on ``AfterToolCallEvent`` so the interrupt fires at tool-call
    granularity rather than waiting for an entire graph node to complete.
    """

    def __init__(self, scan_control: "ScanControl") -> None:
        self._control = scan_control

    def register_hooks(self, registry: Any, **kwargs: Any) -> None:
        from strands.hooks import AfterToolCallEvent
        registry.add_callback(AfterToolCallEvent, self._check_interrupt)

    def _check_interrupt(self, event: Any) -> None:
        if self._control.should_interrupt:
            raise ScanInterruptedException(
                f"Scan {self._control.intent}ed by user after tool call"
            )


class ScanControl:
    """Coordinates pause/stop signals between HTTP handlers and the executor thread.

    The executor thread polls ``should_interrupt`` at each graph node boundary
    (after every ``multiagent_node_stop`` event).  When set, the executor saves
    ``pause_state.json`` to the run directory, emits a terminal WebSocket event,
    and exits cleanly — leaving all completed-node output files on disk so the
    run can be resumed later.
    """

    def __init__(self) -> None:
        self._event = threading.Event()
        self._intent: str = "stop"  # "pause" | "stop"
        # Set by the executor once the run directory has been created.
        # Used by RunManager.resume_run() to locate pause_state.json.
        self.run_dir: str | None = None

    def request_pause(self) -> None:
        """Signal the executor to pause after the current stage completes."""
        self._intent = "pause"
        self._event.set()

    def request_stop(self) -> None:
        """Signal the executor to stop after the current stage completes."""
        self._intent = "stop"
        self._event.set()

    @property
    def should_interrupt(self) -> bool:
        """Return True when a pause or stop has been requested."""
        return self._event.is_set()

    @property
    def intent(self) -> str:
        """Return the requested action: ``"pause"`` or ``"stop"``."""
        return self._intent
