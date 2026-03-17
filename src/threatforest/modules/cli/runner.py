"""Workflow runner for ThreatForest CLI"""
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional
from rich.console import Console

from threatforest.agents.graph import run_graph
from server.registry import create_run_directory


class WorkflowRunner:
    """Execute ThreatForest workflows with progress tracking"""

    def __init__(self):
        self.console = Console()

    def run_full_workflow(
        self,
        project_path: str,
        threat_file_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Execute full workflow via the v2 graph pipeline."""
        abs_path = str(Path(project_path).expanduser().resolve())
        run_dir, project_dir = create_run_directory(abs_path)
        return asyncio.run(run_graph(abs_path, run_dir=str(run_dir)))
