"""Threat Review Node — HITL review of generated threats.

Runs after the threat verifier. Loops until the user clicks "Ready to proceed":
  1. Shows current threats to the user along with 4 guided questions.
  2. Accepts structured edits (priority changes, removals) and optional free-text
     feedback (e.g. "add a threat about X").
  3. Deterministic edits are applied directly to threats.json.
  4. If there is free-text feedback, the threat agent is re-invoked with a
     revision prompt so the LLM can rewrite or add threats accordingly.
  5. Updated threats are shown back to the user — loop continues.

On exit, a structured recap is appended to scanner_context.json's
`interviewer_summary` under a `## Threat statement review` subheading.
"""

from __future__ import annotations

import asyncio
import copy
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from strands.multiagent.base import MultiAgentBase, MultiAgentResult, NodeResult, Status
from strands.agent.agent_result import AgentResult
from strands.types.content import ContentBlock, Message
from strands.telemetry.metrics import EventLoopMetrics

from threatforest.agents.threat_review.enricher import (
    apply_threat_edits,
    append_threat_review_to_summary,
    build_review_summary,
    diff_threats,
)
from threatforest.workspace import LocalFilesystemWorkspace, Workspace


QUESTIONS = [
    "Do these threats make sense for your application?",
    "Do you want to change the priority of any of them?",
    "Are there any false positives?",
    "Are there any new threats you think we should add?",
]


@dataclass
class SimpleInterrupt:
    """Mimics strands Interrupt interface for non-agent interaction rounds."""

    id: str
    reason: dict = field(default_factory=dict)


def _threats_payload(workspace: Workspace) -> list[dict]:
    """Read the current threats list (safe if missing/malformed)."""
    if not workspace.exists("threats.json"):
        return []
    try:
        data = workspace.read_json("threats.json")
    except (json.JSONDecodeError, OSError):
        return []
    return data.get("threats", []) or []


def _summarize_threat_for_ui(t: dict) -> dict:
    """Trim threat fields to what the review UI needs."""
    return {
        "id": t.get("id", ""),
        "title": t.get("title", ""),
        "description": t.get("description", ""),
        "priority": str(t.get("priority", "medium")).lower(),
        "affected_components": t.get("affected_components", []),
    }


class ThreatReviewNode(MultiAgentBase):
    """HITL threat review. Loops until user proceeds."""

    def __init__(
        self,
        state_dir: Path,
        repo_path: str,
        run_dir: str | None,
        interaction_fn: Callable | None,
        node_id: str = "threat_review",
    ):
        self.state_dir = state_dir
        self.workspace: Workspace = LocalFilesystemWorkspace(state_dir)
        self.repo_path = repo_path
        self.run_dir = run_dir
        self.interaction_fn = interaction_fn
        self.id = node_id

    async def invoke_async(self, task, invocation_state=None, **kwargs):
        state_file = self.state_dir / "threats.json"
        scanner_state_file = self.state_dir / "scanner_context.json"

        if self.interaction_fn is None or not self.workspace.exists("threats.json"):
            return self._make_result("Threat review skipped (no interaction_fn).")

        rounds = 0
        feedbacks: list[str] = []
        initial_threats = copy.deepcopy(_threats_payload(self.workspace))
        any_action_taken = False

        while True:
            rounds += 1
            current = _threats_payload(self.workspace)
            payload = {
                "phase": "threat_review",
                "message": (
                    "Review the generated threats. Change priorities, remove false "
                    "positives, or describe any additional threats you'd like added."
                ),
                "questions": QUESTIONS,
                "threats": [_summarize_threat_for_ui(t) for t in current],
            }

            interrupt = SimpleInterrupt(id=f"threat-review-{rounds}", reason=payload)
            responses = await asyncio.to_thread(self.interaction_fn, [interrupt])

            if responses is None:
                # User dismissed/skipped — treat as proceed with no action.
                break

            raw = responses[0].get("interruptResponse", {}).get("response", "")
            parsed = _safe_parse(raw)
            action = parsed.get("action", "proceed")

            if action == "proceed":
                # If this is the very first round and nothing was submitted,
                # fall through with any_action_taken=False so the summary
                # marks the stage as skipped.
                break

            # action == "apply" — structured edits + optional feedback
            edits = parsed.get("edits", {}) or {}
            feedback = (parsed.get("feedback") or "").strip()

            if edits:
                apply_threat_edits(str(state_file), edits)
                any_action_taken = True

            if feedback:
                feedbacks.append(feedback)
                any_action_taken = True
                try:
                    await asyncio.to_thread(
                        self._rerun_threat_agent_with_feedback,
                        feedback,
                    )
                except Exception as exc:  # noqa: BLE001
                    # Don't crash the loop on agent failure — next iteration
                    # will just re-show the threats as they were.
                    print(f"[threat_review] revision agent failed: {exc}")

            # Loop continues — next iteration fetches fresh threats.

        # Build and persist the summary
        final_threats = _threats_payload(self.workspace)
        diff = diff_threats(initial_threats, final_threats)
        review_summary = build_review_summary(
            rounds=rounds,
            applied_edits=[],
            feedbacks=feedbacks,
            added_threat_ids=diff["added"],
            removed_threat_ids=diff["removed"],
            priority_changes=diff["priority_changes"],
            skipped=not any_action_taken,
        )
        try:
            append_threat_review_to_summary(str(scanner_state_file), review_summary)
        except Exception as exc:  # noqa: BLE001
            print(f"[threat_review] failed to persist summary: {exc}")

        return self._make_result("Threat review complete.")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _rerun_threat_agent_with_feedback(self, feedback: str) -> None:
        """Re-invoke the threat agent to revise threats.json based on feedback."""
        from threatforest.agents.threat.agent import create_threat_agent

        agent = create_threat_agent(self.repo_path, run_dir=self.run_dir)
        prompt = (
            "The user has reviewed your previously generated threats and provided "
            "feedback. Read the existing threats.json file (it already contains "
            "your previous output), then revise the threat list according to the "
            "user's feedback below. Preserve each threat's existing priority "
            "(unless the user explicitly asks to change it) and keep existing "
            "threats unless the user explicitly asks to remove them. Add any new "
            "threats the user describes. Use the next available TS00X id for "
            "added threats. Write the complete revised threat list back to the "
            "state file.\n\n"
            f"User feedback:\n{feedback}"
        )
        agent(prompt)

    def _make_result(self, text: str) -> MultiAgentResult:
        msg = Message(role="assistant", content=[ContentBlock(text=text)])
        agent_result = AgentResult(
            stop_reason="end_turn",
            message=msg,
            metrics=EventLoopMetrics(),
            state={},
        )
        return MultiAgentResult(
            status=Status.COMPLETED,
            results={self.id: NodeResult(result=agent_result, status=Status.COMPLETED)},
        )


def _safe_parse(raw: Any) -> dict:
    """Parse the user's WS response as JSON; fall back to treating it as a proceed."""
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return {"action": "proceed"}
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    return {"action": "proceed"}
