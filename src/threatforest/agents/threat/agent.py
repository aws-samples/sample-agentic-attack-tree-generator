"""Threat Agent — generates threat statements from scanner context."""

from pathlib import Path

from strands import Agent
from strands.handlers import null_callback_handler

from threatforest.modules.core.providers.provider_factory import create_model
from threatforest.config import config
from threatforest.tools.sandboxed_file import make_sandboxed_file_read, make_sandboxed_file_write
from threatforest.tools.structural_analyzer import make_structural_analyzer
from threatforest.agents.scanner.agent import STATE_DIR

STATE_FILE = "threats.json"


def _load_prompt() -> str:
    return (Path(__file__).parent / "prompt.md").read_text()


def create_threat_agent(repo_path: str) -> Agent:
    """Create a Threat Agent scoped to the given repository."""
    state_dir = Path(repo_path) / STATE_DIR
    state_dir.mkdir(parents=True, exist_ok=True)

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
    )


def run_threat_agent(repo_path: str) -> str:
    """Run the Threat Agent and return the state file path."""
    agent = create_threat_agent(repo_path)
    agent("Read the scanner context and generate threat statements. Write them to the state file.")
    return str(Path(repo_path) / STATE_DIR / STATE_FILE)
