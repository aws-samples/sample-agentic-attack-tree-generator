"""Property-based tests for RunManager completion events.

Uses Hypothesis to verify that successful pipeline executions always produce
a completion event with a non-empty dashboard_path.
"""

from __future__ import annotations

import shutil
import string
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from server.models import RunConfig
from server.run_manager import ProgressEvent, RunManager

# ---------------------------------------------------------------------------
# Hypothesis settings — minimum 100 examples per property
# ---------------------------------------------------------------------------

PBT_SETTINGS = settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_SAFE_CHARS = string.ascii_lowercase + string.digits + "_-"

safe_name = st.text(
    alphabet=_SAFE_CHARS,
    min_size=1,
    max_size=12,
).filter(lambda n: n not in (".", "..") and not n.startswith("."))

# Strategy for generating dashboard filenames (always .html)
dashboard_filename = st.text(
    alphabet=_SAFE_CHARS,
    min_size=1,
    max_size=20,
).map(lambda n: f"{n}.html")


@st.composite
def successful_run_scenario(draw: st.DrawFn):
    """Generate a temp project directory and a dashboard file path that
    the mock executor will return.

    Returns (tmp_dir, project_path, dashboard_path) where dashboard_path
    is a real file on disk inside an output subdirectory.
    """
    tmp_dir = Path(tempfile.mkdtemp())

    # Create a valid project directory
    project_name = draw(safe_name)
    project_dir = tmp_dir / project_name
    project_dir.mkdir(parents=True)

    # Create an output directory with a dashboard file
    output_name = draw(safe_name)
    output_dir = tmp_dir / output_name
    output_dir.mkdir(parents=True, exist_ok=True)

    dash_name = draw(dashboard_filename)
    dashboard_file = output_dir / dash_name
    dashboard_file.write_text("<html><body>Dashboard</body></html>", encoding="utf-8")

    return tmp_dir, project_dir, output_dir, dashboard_file


# ---------------------------------------------------------------------------
# Property 10: Completion event includes dashboard path
# ---------------------------------------------------------------------------
# Feature: threatforest-landing-page, Property 10: Completion event includes dashboard path
# For any successful pipeline execution, the WebSocket completion event SHALL
# include a non-empty dashboard_path field pointing to an existing file.
# Validates: Requirements 7.1


class TestProperty10CompletionEventIncludesDashboardPath:
    """Property 10: Completion event includes dashboard path."""

    @given(data=successful_run_scenario())
    @PBT_SETTINGS
    def test_completion_event_has_nonempty_dashboard_path(
        self,
        data: tuple[Path, Path, Path, Path],
    ) -> None:
        """For any successful pipeline execution, the completion event
        pushed to the queue includes a non-empty dashboard_path in its
        details."""
        tmp_dir, project_dir, output_dir, dashboard_file = data

        def mock_executor(
            config: RunConfig,
            progress_callback: Callable[[ProgressEvent], None],
        ) -> dict[str, str]:
            return {
                "output_dir": str(output_dir),
                "dashboard_path": str(dashboard_file),
            }

        try:
            mgr = RunManager(executor=mock_executor)
            config = RunConfig(project_path=str(project_dir), threat_source="auto")
            run_id = mgr.start_run(config)
            queue = mgr.get_progress_queue(run_id)

            # Wait for the background thread to finish
            time.sleep(0.3)

            # Drain the queue and find the completion event
            events: list[dict[str, Any]] = []
            while not queue.empty():
                events.append(queue.get_nowait())

            # There must be at least the completion event
            assert len(events) >= 1, "No events found in queue"

            completion = events[-1]
            assert completion["type"] == "stage_complete", (
                f"Last event type is {completion['type']!r}, expected 'stage_complete'"
            )
            assert completion["stage"] == "complete"

            dashboard_path = completion["details"].get("dashboard_path")
            assert dashboard_path is not None, "dashboard_path is missing from details"
            assert isinstance(dashboard_path, str), "dashboard_path is not a string"
            assert len(dashboard_path) > 0, "dashboard_path is empty"
            assert Path(dashboard_path).exists(), (
                f"dashboard_path does not point to an existing file: {dashboard_path}"
            )
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @given(data=successful_run_scenario())
    @PBT_SETTINGS
    def test_completion_event_dashboard_path_is_a_file(
        self,
        data: tuple[Path, Path, Path, Path],
    ) -> None:
        """The dashboard_path in the completion event points to a file,
        not a directory."""
        tmp_dir, project_dir, output_dir, dashboard_file = data

        def mock_executor(
            config: RunConfig,
            progress_callback: Callable[[ProgressEvent], None],
        ) -> dict[str, str]:
            return {
                "output_dir": str(output_dir),
                "dashboard_path": str(dashboard_file),
            }

        try:
            mgr = RunManager(executor=mock_executor)
            config = RunConfig(project_path=str(project_dir), threat_source="auto")
            run_id = mgr.start_run(config)
            queue = mgr.get_progress_queue(run_id)

            time.sleep(0.3)

            events: list[dict[str, Any]] = []
            while not queue.empty():
                events.append(queue.get_nowait())

            assert len(events) >= 1
            completion = events[-1]
            assert completion["type"] == "stage_complete"

            dashboard_path = completion["details"]["dashboard_path"]
            assert Path(dashboard_path).is_file(), (
                f"dashboard_path is not a file: {dashboard_path}"
            )
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @given(data=successful_run_scenario())
    @PBT_SETTINGS
    def test_run_state_also_records_dashboard_path(
        self,
        data: tuple[Path, Path, Path, Path],
    ) -> None:
        """After successful completion, the RunState object also stores
        the dashboard_path consistently with the completion event."""
        tmp_dir, project_dir, output_dir, dashboard_file = data

        def mock_executor(
            config: RunConfig,
            progress_callback: Callable[[ProgressEvent], None],
        ) -> dict[str, str]:
            return {
                "output_dir": str(output_dir),
                "dashboard_path": str(dashboard_file),
            }

        try:
            mgr = RunManager(executor=mock_executor)
            config = RunConfig(project_path=str(project_dir), threat_source="auto")
            run_id = mgr.start_run(config)
            queue = mgr.get_progress_queue(run_id)

            time.sleep(0.3)

            # Drain queue to get the completion event
            events: list[dict[str, Any]] = []
            while not queue.empty():
                events.append(queue.get_nowait())

            completion = events[-1]
            event_dashboard = completion["details"]["dashboard_path"]

            # RunState should match
            state = mgr.active_runs[run_id]
            assert state.status == "complete"
            assert state.dashboard_path == event_dashboard
            assert state.dashboard_path is not None
            assert len(state.dashboard_path) > 0
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
