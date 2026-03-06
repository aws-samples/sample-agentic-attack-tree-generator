"""Progress callback handler — shows tool calls without streaming full LLM text."""

from rich.console import Console
from typing import Any

_console = Console()


class ProgressCallbackHandler:
    """Shows tool invocations during agent execution."""

    def __init__(self, agent_name: str = ""):
        self.agent_name = agent_name
        self._prev_tool = None

    def __call__(self, **kwargs: Any) -> None:
        current_tool_use = kwargs.get("current_tool_use", {})
        if current_tool_use and current_tool_use.get("name"):
            if self._prev_tool != current_tool_use:
                self._prev_tool = current_tool_use
                tool_name = current_tool_use.get("name", "")
                _console.print(f"    [dim]🔧 {tool_name}[/dim]", highlight=False)
