"""Interviewer agent — validates scanner context via human-in-the-loop Q&A.

Uses strands' native interrupt mechanism: the agent calls ask_user, which
triggers an InterruptException via the hook. The caller catches the interrupt,
collects user input, and resumes the agent with the response.
"""

import json
from dataclasses import dataclass, field
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
from threatforest.agents.interviewer.enricher import enrich_scanner_context, apply_scanner_review_edits


# ---------------------------------------------------------------------------
# SimpleInterrupt — lightweight interrupt for non-LLM interaction rounds
# ---------------------------------------------------------------------------

@dataclass
class SimpleInterrupt:
    """Mimics strands Interrupt interface for non-agent interaction rounds.

    Used by ScannerReviewNode and InterviewerNode (fixed questions) so the
    same interaction_fn can handle both real strands interrupts and these
    lightweight ones.
    """
    id: str
    reason: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Fixed interview questions (identical every run)
# ---------------------------------------------------------------------------

# The data-sensitivity question that used to lead this list is now captured
# up front by BusinessContext.data_sensitivity when the user creates the
# application, so the interviewer no longer asks it again.
FIXED_QUESTIONS = [
    "Is this system in production, early design, or early development?",
    "What is the main risk focus — confidentiality, integrity, or availability?",
]

BACK_SENTINEL = "__back__"


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


class ScannerReviewNode(MultiAgentBase):
    """Presents scanner findings to user for confirmation/editing.

    Reads scanner_context.json, sends findings via interaction_fn using a
    SimpleInterrupt with phase="scanner_review", and applies any user edits.
    """

    def __init__(
        self,
        state_dir: Path,
        interaction_fn: Callable | None,
        node_id: str = "scanner_review",
    ):
        self.state_dir = state_dir
        self.interaction_fn = interaction_fn
        self.id = node_id

    async def invoke_async(self, task, invocation_state=None, **kwargs):
        import asyncio

        state_file = self.state_dir / "scanner_context.json"

        if self.interaction_fn is None or not state_file.exists():
            return self._make_result("Scanner review skipped (no interaction_fn).")

        ctx = json.loads(state_file.read_text())

        review_payload = {
            "phase": "scanner_review",
            "message": "Here's what the scanner found. Please confirm or edit before we continue.",
            "scanner_data": {
                "files_analyzed": ctx.get("files_analyzed", []),
                "industry": ctx.get("industry", ""),
                "services": ctx.get("services", []),
                "auth_mechanisms": ctx.get("auth_mechanisms", []),
                # Send as original strings — frontend splits into tokens for editing
                "cloud_provider": ctx.get("cloud_provider", ""),
                "tech_stack": ctx.get("tech_stack", ""),
                "data_sensitivity": ctx.get("data_sensitivity", ""),
                "compliance_requirements": ctx.get("compliance_requirements", []),
            },
        }

        interrupt = SimpleInterrupt(id="scanner-review", reason=review_payload)
        responses = await asyncio.to_thread(self.interaction_fn, [interrupt])

        if responses is not None:
            # Parse user response — expect JSON with edits or plain "confirmed"
            raw = responses[0].get("interruptResponse", {}).get("response", "")
            try:
                edits = json.loads(raw)
                if isinstance(edits, dict) and not edits.get("confirmed_only"):
                    apply_scanner_review_edits(str(state_file), edits)
            except (json.JSONDecodeError, TypeError):
                pass  # Plain text confirmation, no edits needed

        return self._make_result("Scanner review complete.")

    def _make_result(self, text: str):
        agent_result = _make_agent_result(text)
        return MultiAgentResult(
            status=Status.COMPLETED,
            results={self.id: NodeResult(result=agent_result, status=Status.COMPLETED)},
        )


class InterviewerNode(MultiAgentBase):
    """Graph node that runs the interviewer with interrupt-based HITL.

    Phase 1: Sends hardcoded FIXED_QUESTIONS via SimpleInterrupt (no LLM).
              User can go "back" to re-edit scanner findings.
    Phase 2: Feeds answers + scanner context to LLM for follow-ups.
    """

    def __init__(
        self,
        agent: Agent,
        interaction_fn: Callable | None,
        state_dir: Path,
        node_id: str = "interviewer",
    ):
        self.agent = agent
        self.interaction_fn = interaction_fn
        self.state_dir = state_dir
        self.id = node_id

    def _build_scanner_review_interrupt(self) -> SimpleInterrupt:
        """Build a scanner review interrupt from current scanner_context.json."""
        state_file = self.state_dir / "scanner_context.json"
        ctx = json.loads(state_file.read_text()) if state_file.exists() else {}
        return SimpleInterrupt(
            id="scanner-review-back",
            reason={
                "phase": "scanner_review",
                "message": "Edit your scanner findings, then continue.",
                "scanner_data": {
                    "files_analyzed": ctx.get("files_analyzed", []),
                    "industry": ctx.get("industry", ""),
                    "services": ctx.get("services", []),
                    "auth_mechanisms": ctx.get("auth_mechanisms", []),
                    "cloud_provider": ctx.get("cloud_provider", ""),
                    "tech_stack": ctx.get("tech_stack", ""),
                    "data_sensitivity": ctx.get("data_sensitivity", ""),
                    "compliance_requirements": ctx.get("compliance_requirements", []),
                },
            },
        )

    async def invoke_async(self, task, invocation_state=None, **kwargs):
        import asyncio

        if self.interaction_fn is None:
            result_str = await asyncio.to_thread(self._run_skip)
            return self._make_result(result_str)

        # Phase 1: Fixed questions with back-to-scanner-review loop
        while True:
            fixed_interrupt = SimpleInterrupt(
                id="fixed-questions",
                reason={
                    "phase": "interviewer",
                    "message": "A few standard questions before we begin threat modeling.",
                    "questions": FIXED_QUESTIONS,
                },
            )
            fixed_responses = await asyncio.to_thread(self.interaction_fn, [fixed_interrupt])

            if fixed_responses is None:
                result_str = await asyncio.to_thread(self._run_skip)
                return self._make_result(result_str)

            user_text = fixed_responses[0].get("interruptResponse", {}).get("response", "")

            if user_text == BACK_SENTINEL:
                # User wants to go back to scanner review
                review_interrupt = self._build_scanner_review_interrupt()
                review_responses = await asyncio.to_thread(
                    self.interaction_fn, [review_interrupt]
                )
                if review_responses is not None:
                    raw = review_responses[0].get("interruptResponse", {}).get("response", "")
                    try:
                        edits = json.loads(raw)
                        if isinstance(edits, dict) and not edits.get("confirmed_only"):
                            state_file = str(self.state_dir / "scanner_context.json")
                            apply_scanner_review_edits(state_file, edits)
                    except (json.JSONDecodeError, TypeError):
                        pass
                continue  # Loop back to show fixed questions again

            break  # Got real answers, proceed to phase 2

        # Phase 2: Feed answers + scanner context to LLM for follow-ups
        result = await asyncio.to_thread(
            self.agent,
            f"The user answered the standard interview questions as follows:\n\n"
            f"{user_text}\n\n"
            "Read the scanner context file. Based on these answers and any remaining gaps, "
            "either ask targeted follow-up questions using ask_user, or call finalize_interview "
            "if you have enough context.",
        )

        # Multi-turn interrupt loop for LLM follow-ups (unchanged)
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
