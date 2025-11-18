"""Display utilities for ThreatForest CLI using rich"""
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.text import Text
from rich.layout import Layout
from rich.align import Align
from typing import Dict, Any, Optional


class CLIDisplay:
    """Rich-based display utilities for CLI"""
    
    def __init__(self):
        self.console = Console()
    
    def show_welcome(self):
        """Display welcome banner with ASCII art logo"""
        logo = """[bold cyan]
████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗███████╗ ██████╗ ██████╗ ███████╗███████╗████████╗
╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝╚══██╔══╝
   ██║   ███████║██████╔╝█████╗  ███████║   ██║   █████╗  ██║   ██║██████╔╝█████╗  ███████╗   ██║   
   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ╚════██║   ██║   
   ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ██║     ╚██████╔╝██║  ██║███████╗███████║   ██║   
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   
[/bold cyan]

[dim cyan]AI-Driven Threat Modeling & Attack Tree Generation[/dim cyan]"""
        
        panel = Panel(
            Align.center(logo),
            border_style="cyan",
            padding=(1, 2),
            expand=True
        )
        self.console.print(panel)
        self.console.print()
    
    def show_config(self, config: Dict[str, Any]):
        """Display current configuration"""
        config_lines = []
        
        if config.get('aws_profile'):
            config_lines.append(f"[cyan]AWS Profile:[/cyan] {config['aws_profile']}")
        if config.get('bedrock_model'):
            config_lines.append(f"[cyan]Bedrock Model:[/cyan] {config['bedrock_model']}")
        if config.get('neptune_graph_id'):
            config_lines.append(f"[cyan]Neptune Graph:[/cyan] {config['neptune_graph_id']}")
        if config.get('neptune_region'):
            config_lines.append(f"[cyan]Region:[/cyan] {config['neptune_region']}")
        if config.get('embeddings_mode'):
            config_lines.append(f"[cyan]Embeddings Mode:[/cyan] {config['embeddings_mode']}")
        
        if config_lines:
            panel = Panel(
                "\n".join(config_lines),
                title="[bold]Configuration from config.yaml[/bold]",
                border_style="blue",
                padding=(1, 2)
            )
            self.console.print(panel)
            self.console.print()
    
    def show_error(self, error: str, title: str = "Error"):
        """Display error message"""
        panel = Panel(
            f"[red]{error}[/red]",
            title=f"[bold red]❌ {title}[/bold red]",
            border_style="red",
            padding=(1, 2)
        )
        self.console.print(panel)
    
    def show_success(self, message: str, title: str = "Success"):
        """Display success message"""
        panel = Panel(
            f"[green]{message}[/green]",
            title=f"[bold green]✅ {title}[/bold green]",
            border_style="green",
            padding=(1, 2)
        )
        self.console.print(panel)
    
    def show_summary(self, summary: Dict[str, Any]):
        """Display workflow summary as table"""
        table = Table(title="[bold]Workflow Summary[/bold]", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Count", justify="right", style="green")
        
        if 'threats_processed' in summary:
            table.add_row("Threats Processed", str(summary['threats_processed']))
        if 'attack_trees' in summary:
            table.add_row("Attack Trees Generated", str(summary['attack_trees']))
        if 'ttc_mappings' in summary:
            table.add_row("TTC Mappings", str(summary['ttc_mappings']))
        if 'total_mitigations' in summary:
            table.add_row("Mitigations Added", str(summary['total_mitigations']))
        if 'duration' in summary:
            duration_sec = summary['duration'] / 1000 if summary['duration'] > 1000 else summary['duration']
            table.add_row("Duration", f"{duration_sec:.1f}s")
        if 'output_dir' in summary:
            table.add_row("Output Directory", str(summary['output_dir']))
        
        self.console.print()
        self.console.print(table)
        self.console.print()
    
    def create_progress(self, description: str = "Processing") -> Progress:
        """Create a rich progress bar"""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        )
    
    def print(self, message: str, style: Optional[str] = None):
        """Print message with optional style"""
        if style:
            self.console.print(f"[{style}]{message}[/{style}]")
        else:
            self.console.print(message)
    
    def clear(self):
        """Clear the console"""
        self.console.clear()
