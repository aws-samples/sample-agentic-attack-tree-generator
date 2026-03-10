"""TTP Reviewer — LLM agent that refines top-K embedding matches."""

import json
from pathlib import Path

from strands import Agent, tool
from strands.handlers import null_callback_handler

from threatforest.modules.core.providers.provider_factory import create_model
from threatforest.config import config
from threatforest.tools.sandboxed_file import make_sandboxed_file_read, make_sandboxed_file_write
from threatforest.agents.scanner.agent import STATE_DIR
from threatforest.agents.tracing_session import trace_attrs

STATE_FILE = "ttp_mappings.json"


def _load_prompt() -> str:
    return (Path(__file__).parent / "prompt.md").read_text()


def _make_alternatives_tool(repo_path: str):
    """Tool that lets the reviewer drill into top-K candidates for a specific step."""
    candidates_file = Path(repo_path) / STATE_DIR / "ttp_candidates.json"

    @tool
    def get_ttp_alternatives(attack_step_id: str) -> str:
        """Get the top-5 alternative TTP candidates for an attack step that looks wrongly mapped.

        Args:
            attack_step_id: The ID of the attack step to get alternatives for.
        """
        data = json.loads(candidates_file.read_text())
        for c in data.get("ttp_candidates", []):
            if c["attack_step_id"] == attack_step_id:
                return json.dumps(c["top_k"], indent=2)
        return f"No candidates found for step {attack_step_id}"

    return get_ttp_alternatives


def create_ttp_reviewer(repo_path: str) -> Agent:
    """Create a TTP Reviewer Agent."""
    state_dir = Path(repo_path) / STATE_DIR

    summary_file = str(state_dir / "ttp_top1_summary.json")
    mappings_file = str(state_dir / STATE_FILE)

    tools = [
        make_sandboxed_file_read([summary_file]),
        make_sandboxed_file_write([mappings_file]),
        _make_alternatives_tool(repo_path),
    ]

    system_prompt = _load_prompt()
    system_prompt += (
        f"\n\n## Paths\n"
        f"- TTP top-1 mappings: `{summary_file}`\n"
        f"- Write output to: `{mappings_file}`\n"
    )

    model = create_model(config, temperature=0)

    return Agent(
        model=model,
        system_prompt=system_prompt,
        tools=tools,
        callback_handler=null_callback_handler(),
        trace_attributes=trace_attrs("ttp-reviewer"),
    )


def run_ttp_reviewer(repo_path: str) -> str:
    """Run the TTP Reviewer and return the state file path."""
    agent = create_ttp_reviewer(repo_path)
    agent("Read the top-1 TTP mappings. Review each one. If any look wrong, use get_ttp_alternatives to check alternatives. Write all final mappings to the state file.")
    return str(Path(repo_path) / STATE_DIR / STATE_FILE)
