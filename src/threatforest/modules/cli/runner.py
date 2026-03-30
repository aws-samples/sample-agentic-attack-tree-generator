"""Workflow runner for ThreatForest CLI"""
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional, List

from rich.console import Console
from rich.panel import Panel

from threatforest.agents.graph import run_graph
from server.registry import create_run_directory


def _make_cli_interaction_fn(console: Console):
    """Create an interaction function that prompts the user in the terminal."""

    def interaction_fn(interrupts):
        for interrupt in interrupts:
            reason = interrupt.reason or {}
            console.print()
            console.print(Panel(
                reason.get("message", "The interviewer has questions for you."),
                title="[bold cyan]Context Validation[/bold cyan]",
                border_style="cyan",
            ))

            questions = reason.get("questions", [])
            for i, q in enumerate(questions, 1):
                console.print(f"  [bold]{i}.[/bold] {q}")

            console.print()
            console.print("[dim]Type your response below, or 'skip' to proceed without answering.[/dim]")
            console.print()

            try:
                response = console.input("[cyan]> [/cyan]")
            except (EOFError, KeyboardInterrupt):
                return None

            if not response or response.strip().lower() in ("skip", "done", "s"):
                return None

            return [{"interruptResponse": {"interruptId": interrupt.id, "response": response}}]

        return None

    return interaction_fn


class WorkflowRunner:
    """Execute ThreatForest workflows with progress tracking"""

    def __init__(self):
        self.console = Console()

    def run_full_workflow(
        self,
        project_path: str,
        threat_file_path: Optional[str] = None,
        frameworks: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Execute full workflow via the v2 graph pipeline."""
        abs_path = str(Path(project_path).expanduser().resolve())
        run_dir, project_dir = create_run_directory(abs_path)
        cli_interaction_fn = _make_cli_interaction_fn(self.console)
        return asyncio.run(run_graph(
            abs_path,
            run_dir=str(run_dir),
            frameworks=frameworks,
            interaction_fn=cli_interaction_fn,
        ))
