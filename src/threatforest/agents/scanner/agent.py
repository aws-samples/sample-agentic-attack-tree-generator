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
    """Return the state directory — uses *run_dir*/state if provided, else legacy path.

    Only creates the directory when *run_dir* is given (centralized runs).
    The legacy fallback returns the path without creating it so that scanned
    projects are never polluted with a ``.threatforest/`` folder.
    """
    if run_dir:
        sd = Path(run_dir) / "state"
        sd.mkdir(parents=True, exist_ok=True)
    else:
        sd = Path(repo_path) / STATE_DIR
    return sd


def _load_prompt() -> str:
    return (Path(__file__).parent / "prompt.md").read_text()


def _count_source_files(repo_path: str) -> int:
    """Quick count of analyzable files to determine repo size category.

    Uses an exclusion-based approach: any file that isn't a known binary
    artifact or hidden file is considered analyzable. This lets ThreatForest
    run on repos containing source code, documentation, diagrams, images,
    architecture PDFs, IaC templates, or any other informational content.
    """
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "target"}
    skip_exts = {
        # Compiled / binary artifacts
        ".pyc", ".pyo", ".class", ".o", ".so", ".dylib", ".dll", ".exe",
        ".whl", ".egg", ".jar", ".war",
        # Package archives
        ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
        # OS junk
        ".ds_store",
    }
    count = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            if f.startswith("."):
                continue
            if Path(f).suffix.lower() not in skip_exts:
                count += 1
        if count >= 50:
            return count
    return count


def _load_seeded_business_context(state_file: str) -> dict | None:
    """Return a pre-seeded ``business_context`` block if the state file exists.

    The v2 UX pre-populates ``scanner_context.json`` with user-provided
    business context before the scanner runs (see ``server.executor.
    _seed_scanner_context``). Surfacing that block in the system prompt —
    in addition to it being available through the file the agent reads —
    matches the existing handoff convention of "prompt + file".
    """
    path = Path(state_file)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    bc = data.get("business_context")
    return bc if isinstance(bc, dict) and bc else None


def create_scanner_agent(repo_path: str, run_dir: str | None = None) -> Agent:
    """Create a Scanner Agent scoped to the given repository."""
    state_dir = resolve_state_dir(repo_path, run_dir)
    state_file = str(state_dir / STATE_FILE)

    tools = [
        make_structural_analyzer(repo_path),
        # Allow the agent to read repo files *and* its own seeded state file
        # so it can merge business context into the output rather than
        # overwriting the pre-populated fields.
        make_sandboxed_file_read([repo_path, state_file]),
        make_sandboxed_file_write([state_file]),
    ]

    file_count = _count_source_files(repo_path)
    size_hint = "small" if file_count < 50 else "large"

    system_prompt = _load_prompt()
    system_prompt += f"\n\n## Repo Info\n- Path: `{repo_path}`\n- Source files: ~{file_count}\n- Size category: **{size_hint}**\n- Write output to: `{state_file}`\n"

    # When the run is linked to a persistent Application, the executor has
    # seeded `state_file` with a `business_context` block and top-level
    # `compliance_requirements` / `data_sensitivity`. Surface it in-prompt so
    # the agent can treat it as authoritative context while analysing the
    # repo, and remind it to preserve (not overwrite) those fields.
    seeded_bc = _load_seeded_business_context(state_file)
    if seeded_bc is not None:
        system_prompt += (
            "\n\n## User-Provided Business Context (authoritative)\n"
            "The state file has been pre-populated with the following\n"
            "user-provided business context. Treat these fields as the\n"
            "source of truth. Do not overwrite them; preserve them when\n"
            "you write your output, and let them shape which parts of the\n"
            "repo you prioritise.\n\n"
            f"```json\n{json.dumps(seeded_bc, indent=2)}\n```\n"
        )

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
