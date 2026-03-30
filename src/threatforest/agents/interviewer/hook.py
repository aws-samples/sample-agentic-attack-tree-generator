"""Interrupt hook for the interviewer agent's ask_user tool.

Uses strands' built-in interrupt mechanism on BeforeToolCallEvent.
On first invocation (no response available), raises InterruptException
which stops the agent and returns the interrupt to the caller.
On second invocation (after resume with response), returns the user's
response text so the tool can proceed normally.
"""

from typing import Any

from strands.hooks import BeforeToolCallEvent, HookProvider, HookRegistry


class InterviewerInterruptHook(HookProvider):
    """Interrupts agent execution when ask_user is called, routing to the human."""

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(BeforeToolCallEvent, self.handle_ask_user)

    def handle_ask_user(self, event: BeforeToolCallEvent) -> None:
        if event.tool_use["name"] != "ask_user":
            return

        tool_input = event.tool_use.get("input", {})
        # event.interrupt() raises InterruptException on first call,
        # returns the user's response string on second call (after resume).
        response = event.interrupt(
            "interviewer_question",
            reason={
                "message": tool_input.get("message", ""),
                "questions": tool_input.get("questions", []),
                "context_summary": tool_input.get("context_summary", {}),
            },
        )
        # If we get here, we have a response — cancel the real tool call
        # and inject the response as the tool result directly.
        event.cancel_tool = f"User response: {response}"
