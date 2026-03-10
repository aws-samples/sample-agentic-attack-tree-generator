"""Mitigation Agent — LLM agent that synthesizes actionable mitigations."""

from pathlib import Path

from strands import Agent
from strands.handlers import null_callback_handler

from threatforest.modules.core.providers.provider_factory import create_model
from threatforest.config import config
from threatforest.tools.sandboxed_file import make_sandboxed_file_read, make_sandboxed_file_write
from threatforest.agents.scanner.agent import STATE_DIR
from threatforest.agents.tracing_session import trace_attrs

STATE_FILE = "mitigations.json"


def _load_prompt() -> str:
    return (Path(__file__).parent / "prompt.md").read_text()


def create_mitigation_agent(repo_path: str) -> Agent:
    """Create a Mitigation Agent."""
    state_dir = Path(repo_path) / STATE_DIR

    read_files = [
        str(state_dir / "ttp_mappings.json"),
        str(state_dir / "scanner_context.json"),
        str(state_dir / "attack_trees.json"),
    ]

    # Control candidates may or may not exist (AWS conditional)
    controls_file = state_dir / "control_candidates.json"
    if controls_file.exists():
        read_files.append(str(controls_file))

    out_file = str(state_dir / STATE_FILE)

    tools = [
        make_sandboxed_file_read(read_files),
        make_sandboxed_file_write([out_file]),
    ]

    system_prompt = _load_prompt()
    system_prompt += (
        f"\n\n## Paths\n"
        f"- TTP mappings: `{state_dir / 'ttp_mappings.json'}`\n"
        f"- Scanner context: `{state_dir / 'scanner_context.json'}`\n"
        f"- Attack trees: `{state_dir / 'attack_trees.json'}`\n"
        f"- Control candidates (if exists): `{controls_file}`\n"
        f"- Write output to: `{out_file}`\n"
    )

    model = create_model(config, temperature=0)

    return Agent(
        model=model,
        system_prompt=system_prompt,
        tools=tools,
        callback_handler=null_callback_handler(),
        trace_attributes=trace_attrs("mitigation"),
    )


def run_mitigation_agent(repo_path: str) -> str:
    """Run the Mitigation Agent and return the state file path."""
    agent = create_mitigation_agent(repo_path)
    agent("Read all state files. For each attack step, synthesize an actionable mitigation with evidence. Write to the state file.")
    return str(Path(repo_path) / STATE_DIR / STATE_FILE)
