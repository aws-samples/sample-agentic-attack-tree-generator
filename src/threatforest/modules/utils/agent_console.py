"""Console display utilities for agent status and progress"""
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from typing import Optional


class AgentConsole:
    """Provides consistent console output for agent operations"""
    
    def __init__(self, console: Optional[Console] = None, show_errors: bool = True):
        """Initialize AgentConsole
        
        Args:
            console: Optional Rich Console instance
            show_errors: Whether to display errors in CLI (default: True)
        """
        self.console = console or Console()
        self.show_errors = show_errors
    
    def show_agent_start(self, agent_name: str, description: str):
        """Show when an agent starts working"""
        panel = Panel(
            f"[bold cyan]{description}[/bold cyan]",
            title=f"[bold bright_blue]🤖 {agent_name}[/bold bright_blue]",
            border_style="bright_blue",
            box=box.ROUNDED,
            padding=(0, 2)
        )
        self.console.print()
        self.console.print(panel)
    
    def show_tool_use(self, tool_name: str, details: str, status: str = "running"):
        """Show when an agent uses a tool"""
        icons = {
            "running": "🔧",
            "success": "✓",
            "error": "✗"
        }
        colors = {
            "running": "yellow",
            "success": "green",
            "error": "red"
        }
        
        icon = icons.get(status, "🔧")
        color = colors.get(status, "yellow")
        
        self.console.print(f"  {icon} [{color}]Using tool: {tool_name}[/{color}]")
        self.console.print(f"    [dim]{details}[/dim]")
    
    def show_agent_thinking(self, message: str):
        """Show agent reasoning or analysis"""
        self.console.print(f"  💭 [cyan]{message}[/cyan]")
    
    def show_agent_action(self, action: str, result: Optional[str] = None):
        """Show agent action and optional result"""
        self.console.print(f"  ├─ [yellow]{action}[/yellow]")
        if result:
            self.console.print(f"  │  [dim]{result}[/dim]")
    
    def show_agent_spinner(self, message: str, spinner: str = "dots"):
        """
        Show agent action with animated spinner
        
        Returns a context manager that displays a spinner while work is being done.
        
        Usage:
            with agent_console.show_agent_spinner("Processing..."):
                # do work
                result = agent.process()
            # Spinner stops automatically
        
        Args:
            message: Status message to display
            spinner: Spinner style (dots, line, arc, etc.)
            
        Returns:
            Status context manager
        """
        return self.console.status(
            f"  ├─ {message}",
            spinner=spinner,
            spinner_style="yellow"
        )
    
    def show_agent_complete(self, summary: str, success: bool = True):
        """Show when agent completes"""
        icon = "✅" if success else "⚠️"
        color = "green" if success else "yellow"
        self.console.print(f"  └─ [{color}]{icon} {summary}[/{color}]")
        self.console.print()
    
    def show_agent_error(self, error: str):
        """Show agent error (if show_errors is enabled)
        
        Args:
            error: Error message to display
            
        Note:
            This method respects the show_errors configuration.
            Errors are always logged to file regardless of this setting.
        """
        if self.show_errors:
            self.console.print(f"  └─ [red]❌ Error: {error}[/red]")
            self.console.print()
    
    def show_collaboration(self, from_agent: str, to_agent: str, data_summary: str):
        """Show when agents collaborate"""
        self.console.print()
        self.console.print(f"[bold magenta]🤝 Agent Collaboration[/bold magenta]")
        self.console.print(f"   {from_agent} [dim]→[/dim] {to_agent}")
        self.console.print(f"   [dim]Sharing: {data_summary}[/dim]")
        self.console.print()
