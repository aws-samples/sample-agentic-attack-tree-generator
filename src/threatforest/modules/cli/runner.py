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
    from rich.table import Table

    def interaction_fn(interrupts):
        for interrupt in interrupts:
            reason = interrupt.reason or {}
            phase = reason.get("phase", "interviewer")

            if phase == "scanner_review":
                return _handle_scanner_review(console, interrupt, reason)

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

    def _handle_scanner_review(console, interrupt, reason):
        """Present scanner findings as a Rich table for CLI review."""
        import json

        scanner_data = reason.get("scanner_data", {})

        console.print()
        table = Table(title="Scanner Findings", border_style="cyan", show_lines=True)
        table.add_column("Field", style="bold")
        table.add_column("Value")

        table.add_row("Cloud Provider", scanner_data.get("cloud_provider", "unknown"))
        table.add_row("Tech Stack", scanner_data.get("tech_stack", ""))
        table.add_row("Industry", scanner_data.get("industry", "") or "not detected")
        table.add_row("Services", ", ".join(scanner_data.get("services", [])) or "none")
        table.add_row("Auth Mechanisms", ", ".join(scanner_data.get("auth_mechanisms", [])) or "none")
        table.add_row("Compliance", ", ".join(scanner_data.get("compliance_requirements", [])) or "none")
        table.add_row("Data Sensitivity", scanner_data.get("data_sensitivity", "") or "not detected")
        table.add_row("Files Analyzed", str(len(scanner_data.get("files_analyzed", []))))

        console.print(table)
        console.print()
        console.print("[dim]Press Enter to confirm, or type edits as JSON (e.g. {\"industry\": \"healthcare\"}).[/dim]")
        console.print("[dim]Type 'skip' to proceed without review.[/dim]")
        console.print()

        try:
            response = console.input("[cyan]> [/cyan]")
        except (EOFError, KeyboardInterrupt):
            return None

        if not response or response.strip().lower() in ("skip", "s"):
            return None

        if not response.strip() or response.strip().lower() in ("y", "yes", "confirm", "ok"):
            response = json.dumps({"confirmed_only": True})

        return [{"interruptResponse": {"interruptId": interrupt.id, "response": response}}]

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
