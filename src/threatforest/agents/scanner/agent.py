"""Scanner Agent — explores a repository and builds ProjectContext."""

import json
import os
from pathlib import Path

from strands import Agent
from strands.handlers import null_callback_handler

from threatforest.modules.core.providers.provider_factory import create_model
from threatforest.config import config
from threatforest.tools.sandboxed_file import make_sandboxed_file_read, make_sandboxed_file_write
from threatforest.tools.structural_analyzer import make_structural_analyzer
from threatforest.agents.tracing_session import trace_attrs

STATE_DIR = ".threatforest/state"  # legacy default, overridden by run_dir
STATE_FILE = "scanner_context.json"


def resolve_state_dir(repo_path: str, run_dir: str | None = None) -> Path:
    """Return the state directory — uses *run_dir*/state if provided, else legacy path."""
    if run_dir:
        sd = Path(run_dir) / "state"
    else:
        sd = Path(repo_path) / STATE_DIR
    sd.mkdir(parents=True, exist_ok=True)
    return sd


def _load_prompt() -> str:
    return (Path(__file__).parent / "prompt.md").read_text()


def _count_source_files(repo_path: str) -> int:
    """Quick count of source files to determine repo size category."""
    source_exts = {".py", ".js", ".ts", ".java", ".go", ".rb", ".rs", ".c", ".cpp", ".cs", ".php"}
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "target"}
    count = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        count += sum(1 for f in files if Path(f).suffix.lower() in source_exts)
        if count >= 50:
            return count
    return count


def create_scanner_agent(repo_path: str, run_dir: str | None = None) -> Agent:
    """Create a Scanner Agent scoped to the given repository."""
    state_dir = resolve_state_dir(repo_path, run_dir)
    state_file = str(state_dir / STATE_FILE)

    tools = [
        make_structural_analyzer(repo_path),
        make_sandboxed_file_read([repo_path]),
        make_sandboxed_file_write([state_file]),
    ]

    file_count = _count_source_files(repo_path)
    size_hint = "small" if file_count < 50 else "large"

    system_prompt = _load_prompt()
    system_prompt += f"\n\n## Repo Info\n- Path: `{repo_path}`\n- Source files: ~{file_count}\n- Size category: **{size_hint}**\n- Write output to: `{state_file}`\n"

    model = create_model(config, temperature=0)

    return Agent(
        model=model,
        system_prompt=system_prompt,
        tools=tools,
        callback_handler=null_callback_handler(),
        trace_attributes=trace_attrs("scanner"),
    )


def run_scanner(repo_path: str, run_dir: str | None = None) -> str:
    """Run the Scanner Agent and return the state file path."""
    agent = create_scanner_agent(repo_path, run_dir=run_dir)
    agent("Analyze this repository and write the project context to the state file.")
    state_dir = resolve_state_dir(repo_path, run_dir)
    return str(state_dir / STATE_FILE)
