"""Interviewer agent — validates scanner context via human-in-the-loop Q&A.

Uses strands' native interrupt mechanism: the agent calls ask_user, which
triggers an InterruptException via the hook. The caller catches the interrupt,
collects user input, and resumes the agent with the response.
"""

import json
from pathlib import Path
from typing import Any, Callable

from strands import Agent, tool
from strands.handlers import null_callback_handler
from strands.multiagent.base import MultiAgentBase, MultiAgentResult, NodeResult, Status
from strands.agent.agent_result import AgentResult
from strands.types.content import ContentBlock, Message
from strands.telemetry.metrics import EventLoopMetrics

from threatforest.modules.core.providers.provider_factory import create_model
from threatforest.config import config
from threatforest.tools.sandboxed_file import make_sandboxed_file_read
from threatforest.agents.scanner.agent import resolve_state_dir
from threatforest.agents.tracing_session import trace_attrs
from threatforest.agents.interviewer.hook import InterviewerInterruptHook
from threatforest.agents.interviewer.enricher import enrich_scanner_context


def _load_prompt() -> str:
    return (Path(__file__).parent / "prompt.md").read_text()


def _make_finalize_tool(state_file: str):
    """Create the finalize_interview tool bound to the state file."""

    @tool
    def finalize_interview(
        confidence: str,
        additional_context: dict,
        summary: str,
    ) -> str:
        """Finalize the interview and write enriched context to scanner_context.json.

        Args:
            confidence: Assessment of context completeness — "high", "medium", or "low".
            additional_context: Dict of user-provided context to merge into scanner_context.
                May include keys like auth_mechanisms, services, compliance_requirements,
                data_sensitivity, deployment_model, industry, and any other relevant fields.
            summary: Brief summary of what was learned in the interview.
        """
        enrich_scanner_context(state_file, additional_context, confidence, summary)
        return f"Interview finalized. Confidence: {confidence}. Context written to {state_file}."

    return finalize_interview


@tool
def ask_user(
    message: str,
    questions: list[str],
    context_summary: dict,
) -> str:
    """Ask the user questions about their application to fill gaps in the scanner context.

    This tool triggers an interrupt — the agent will pause and the caller
    will route the questions to the user. When the user responds, the agent
    resumes with their answer.

    Args:
        message: A SHORT 1-2 sentence intro. No preamble or flattery. Just state
            what gaps you need filled. Example: "I need details about your deployment
            model and access controls."
        questions: A list of 2-5 separate question strings. Each question is its own
            list item — do NOT put all questions in the message field. Keep questions
            as plain text without markdown formatting.
        context_summary: Summary of what the scanner already found, for user context.
            Should include keys like tech_stack, services, auth_mechanisms, etc.
    """
    # The InterviewerInterruptHook intercepts this tool call via
    # BeforeToolCallEvent and triggers an interrupt. This body only
    # executes if somehow the hook didn't fire (shouldn't happen).
    return "No response received — the interrupt hook may not be configured."


def create_interviewer_agent(repo_path: str, run_dir: str | None = None) -> Agent:
    """Create an interviewer agent scoped to the given repository."""
    state_dir = resolve_state_dir(repo_path, run_dir)
    state_file = str(state_dir / "scanner_context.json")

    tools = [
        make_sandboxed_file_read([repo_path, str(state_dir)]),
        ask_user,
        _make_finalize_tool(state_file),
    ]

    system_prompt = _load_prompt()
    system_prompt += (
        f"\n\n## Context\n"
        f"- Scanner context file: `{state_file}`\n"
        f"- Repository path: `{repo_path}`\n"
    )

    model = create_model(config, temperature=0.3)

    return Agent(
        model=model,
        system_prompt=system_prompt,
        tools=tools,
        hooks=[InterviewerInterruptHook()],
        callback_handler=null_callback_handler(),
        trace_attributes=trace_attrs("interviewer"),
    )


class InterviewerNode(MultiAgentBase):
    """Graph node that runs the interviewer with interrupt-based HITL.

    Encapsulates the multi-turn interrupt loop within the node so the
    graph executor doesn't need special interrupt handling.
    """

    def __init__(
        self,
        agent: Agent,
        interaction_fn: Callable | None,
        node_id: str = "interviewer",
    ):
        self.agent = agent
        self.interaction_fn = interaction_fn
        self.id = node_id

    async def invoke_async(self, task, invocation_state=None, **kwargs):
        import asyncio

        if self.interaction_fn is None:
            # No interaction function — skip interview, finalize with low confidence
            result_str = await asyncio.to_thread(self._run_skip)
            return self._make_result(result_str)

        result = await asyncio.to_thread(
            self.agent,
            "Read the scanner context file and evaluate its completeness. "
            "Then ask the user targeted questions about any gaps you find.",
        )

        # Multi-turn interrupt loop
        while result.stop_reason == "interrupt" and result.interrupts:
            responses = await asyncio.to_thread(self.interaction_fn, result.interrupts)
            if responses is None:
                # User skipped — must resume with proper interruptResponse format
                skip_responses = [
                    {
                        "interruptResponse": {
                            "interruptId": interrupt.id,
                            "response": (
                                "The user chose to skip the interview. "
                                "Call finalize_interview immediately with "
                                "confidence='low', an empty additional_context "
                                "dict, and a summary noting the interview was skipped."
                            ),
                        }
                    }
                    for interrupt in result.interrupts
                ]
                result = await asyncio.to_thread(self.agent, skip_responses)
                break
            result = await asyncio.to_thread(self.agent, responses)

        agent_result = _make_agent_result(str(result))
        return MultiAgentResult(
            status=Status.COMPLETED,
            results={self.id: NodeResult(result=agent_result, status=Status.COMPLETED)},
        )

    def _run_skip(self) -> str:
        """Skip interview — just write low confidence to scanner context."""
        result = self.agent(
            "The interview is being skipped. Call finalize_interview immediately "
            "with confidence='low', an empty additional_context dict, and a summary "
            "noting the interview was skipped."
        )
        return str(result)

    def _make_result(self, text: str):
        agent_result = _make_agent_result(text)
        return MultiAgentResult(
            status=Status.COMPLETED,
            results={self.id: NodeResult(result=agent_result, status=Status.COMPLETED)},
        )


def _make_agent_result(text: str) -> AgentResult:
    msg = Message(role="assistant", content=[ContentBlock(text=text)])
    return AgentResult(stop_reason="end_turn", message=msg, metrics=EventLoopMetrics(), state={})
