"""Threat Agent — generates threat statements from scanner context."""

from pathlib import Path

from strands import Agent
from strands.handlers import null_callback_handler

from threatforest.modules.core.providers.provider_factory import create_model
from threatforest.config import config
from threatforest.tools.sandboxed_file import make_sandboxed_file_read, make_sandboxed_file_write
from threatforest.tools.structural_analyzer import make_structural_analyzer
from threatforest.agents.scanner.agent import STATE_DIR, resolve_state_dir
from threatforest.agents.tracing_session import trace_attrs

STATE_FILE = "threats.json"


def _load_prompt() -> str:
    return (Path(__file__).parent / "prompt.md").read_text()


def create_threat_agent(repo_path: str, run_dir: str | None = None) -> Agent:
    """Create a Threat Agent scoped to the given repository."""
    state_dir = resolve_state_dir(repo_path, run_dir)

    scanner_state = str(state_dir / "scanner_context.json")
    threat_state = str(state_dir / STATE_FILE)

    tools = [
        make_sandboxed_file_read([scanner_state, repo_path]),
        make_sandboxed_file_write([threat_state]),
        make_structural_analyzer(repo_path),
    ]

    system_prompt = _load_prompt()
    system_prompt += f"\n\n## Paths\n- Scanner context: `{scanner_state}`\n- Write output to: `{threat_state}`\n"

    model = create_model(config, temperature=0)

    return Agent(
        model=model,
        system_prompt=system_prompt,
        tools=tools,
        callback_handler=null_callback_handler(),
        trace_attributes=trace_attrs("threat"),
    )


def run_threat_agent(repo_path: str, run_dir: str | None = None) -> str:
    """Run the Threat Agent and return the state file path."""
    agent = create_threat_agent(repo_path, run_dir=run_dir)
    agent("Read the scanner context and generate threat statements. Write them to the state file.")
    state_dir = resolve_state_dir(repo_path, run_dir)
    return str(state_dir / STATE_FILE)
