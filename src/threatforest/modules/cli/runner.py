"""Workflow runner for ThreatForest CLI"""
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional
from rich.console import Console

from threatforest.agents.graph import run_graph


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
        return asyncio.run(run_graph(abs_path))
