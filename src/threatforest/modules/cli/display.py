"""Display utilities for ThreatForest CLI using rich"""
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.text import Text
from rich.layout import Layout
from rich.align import Align
from rich.live import Live
from rich.tree import Tree
from rich import box
from typing import Dict, Any, Optional
import time


class CLIDisplay:
    """Rich-based display utilities for CLI"""
    
    def __init__(self):
        self.console = Console()
    
    def show_welcome(self):
        """Display welcome banner with modern gradient logo"""
        logo = """[bold cyan]
████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗███████╗ ██████╗ ██████╗ ███████╗███████╗████████╗
╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝╚══██╔══╝
   ██║   ███████║██████╔╝█████╗  ███████║   ██║   █████╗  ██║   ██║██████╔╝█████╗  ███████╗   ██║   
   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ╚════██║   ██║   
   ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ██║     ╚██████╔╝██║  ██║███████╗███████║   ██║   
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   
[/bold cyan]

[bold blue]🛡️  AI-Driven Threat Modeling & Attack Tree Generation[/bold blue]"""
        
        panel = Panel(
            Align.center(logo),
            border_style="blue",
            box=box.DOUBLE,
            padding=(1, 2),
            expand=True
        )
        self.console.print(panel)
        self.console.print()
    
    def show_config(self, config: Dict[str, Any]):
        """Display current configuration with icons and better formatting"""
        config_lines = []
        
        # New format: model_provider, model_id, embeddings_model, ttc_threshold
        if config.get('model_provider'):
            config_lines.append(f"[bold blue]🤖 Model Provider[/bold blue]       {config['model_provider']}")
        if config.get('model_id'):
            model_id = config['model_id']
            # Truncate long model IDs for display
            if len(model_id) > 50:
                model_id = model_id[:47] + "..."
            config_lines.append(f"[bold blue]🎯 Model ID[/bold blue]             {model_id}")
        if config.get('embeddings_model'):
            config_lines.append(f"[bold blue]🧠 Embeddings Model[/bold blue]     {config['embeddings_model']}")
        if config.get('ttc_threshold'):
            config_lines.append(f"[bold blue]📊 TTC Threshold[/bold blue]        {config['ttc_threshold']}")
        
        # Legacy support (old keys for backward compatibility)
        if config.get('aws_profile'):
            config_lines.append(f"[bold blue]🔧 AWS Profile[/bold blue]          {config['aws_profile']}")
        if config.get('bedrock_model'):
            config_lines.append(f"[bold blue]🤖 Bedrock Model[/bold blue]        {config['bedrock_model']}")
        if config.get('graph_file'):
            config_lines.append(f"[bold blue]📁 Graph File[/bold blue]           {config['graph_file']}")
        
        if config_lines:
            panel = Panel(
                "\n".join(config_lines),
                title="[bold bright_blue]⚙️  Configuration[/bold bright_blue]",
                border_style="bright_blue",
                box=box.ROUNDED,
                padding=(1, 2)
            )
            self.console.print(panel)
            self.console.print()
    
    def show_error(self, error: str, title: str = "Error", suggestions: Optional[list] = None):
        """Display error message with optional suggestions"""
        content = f"[bold red]❌ {error}[/bold red]\n"
        
        if suggestions:
            content += "\n[bold yellow]💡 Suggestions:[/bold yellow]\n"
            for suggestion in suggestions:
                content += f"  • {suggestion}\n"
        
        panel = Panel(
            content.rstrip(),
            title=f"[bold red]{title}[/bold red]",
            border_style="red",
            box=box.ROUNDED,
            padding=(1, 2)
        )
        self.console.print(panel)
        self.console.print()
    
    def show_success(self, message: str, title: str = "Success"):
        """Display success message with icon"""
        panel = Panel(
            f"[bold green]✅ {message}[/bold green]",
            title=f"[bold bright_green]{title}[/bold bright_green]",
            border_style="bright_green",
            box=box.ROUNDED,
            padding=(1, 2)
        )
        self.console.print(panel)
        self.console.print()
    
    def show_summary(self, summary: Dict[str, Any]):
        """Display workflow summary with modern dashboard layout"""
        # Create summary content with icons
        content = "[bold bright_blue]📊 Summary[/bold bright_blue]\n\n"
        
        if 'threats_processed' in summary:
            content += f"[cyan]├─[/cyan] Threats Processed    [bold bright_green]{summary['threats_processed']}[/bold bright_green]\n"
        if 'attack_trees' in summary:
            content += f"[cyan]├─[/cyan] Attack Trees         [bold bright_green]{summary['attack_trees']}[/bold bright_green]\n"
        if 'ttc_mappings' in summary:
            content += f"[cyan]├─[/cyan] TTC Mappings         [bold bright_green]{summary['ttc_mappings']}[/bold bright_green]\n"
        if 'total_mitigations' in summary:
            content += f"[cyan]└─[/cyan] Mitigations Added    [bold bright_green]{summary['total_mitigations']}[/bold bright_green]\n"
        
        if 'duration' in summary:
            duration_sec = summary['duration'] / 1000 if summary['duration'] > 1000 else summary['duration']
            content += f"\n[bold bright_blue]⏱️  Duration[/bold bright_blue] {duration_sec:.1f}s\n"
        
        if 'output_dir' in summary:
            content += f"[bold bright_blue]📂 Output[/bold bright_blue]   {summary['output_dir']}\n"
        
        panel = Panel(
            content.rstrip(),
            title="[bold bright_green]✅ Workflow Complete[/bold bright_green]",
            border_style="bright_green",
            box=box.DOUBLE,
            padding=(1, 2)
        )
        
        self.console.print()
        self.console.print(panel)
        self.console.print()
    
    def create_progress(self, description: str = "Processing") -> Progress:
        """Create a modern rich progress bar with time elapsed"""
        return Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(
                complete_style="bright_green",
                finished_style="bright_green",
                pulse_style="cyan"
            ),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console
        )
    
    def show_step_header(self, step_num: int, total_steps: int, title: str, description: str = ""):
        """Show a step header with progress indicator"""
        header = f"[bold bright_blue]Step {step_num}/{total_steps}:[/bold bright_blue] [bold]{title}[/bold]"
        if description:
            header += f"\n[dim]{description}[/dim]"
        
        panel = Panel(
            header,
            border_style="bright_blue",
            box=box.ROUNDED,
            padding=(0, 2)
        )
        self.console.print()
        self.console.print(panel)
    
    def show_info(self, message: str, title: str = "Info"):
        """Display informational message"""
        panel = Panel(
            f"[bold blue]ℹ️  {message}[/bold blue]",
            title=f"[bold bright_blue]{title}[/bold bright_blue]",
            border_style="bright_blue",
            box=box.ROUNDED,
            padding=(1, 2)
        )
        self.console.print(panel)
        self.console.print()
    
    def show_warning(self, message: str, title: str = "Warning"):
        """Display warning message"""
        panel = Panel(
            f"[bold yellow]⚠️  {message}[/bold yellow]",
            title=f"[bold yellow]{title}[/bold yellow]",
            border_style="yellow",
            box=box.ROUNDED,
            padding=(1, 2)
        )
        self.console.print(panel)
        self.console.print()
    
    def show_review_config(self, mode: str, project_path: str = None, threat_model: str = None,
                          input_dir: str = None, output_dir: str = None):
        """Show configuration review before execution"""
        content = f"[bold bright_blue]Mode[/bold bright_blue]          {mode.replace('_', ' ').title()}\n"
        
        if project_path:
            content += f"[bold bright_blue]Project[/bold bright_blue]       {project_path}\n"
        if threat_model:
            content += f"[bold bright_blue]Threat Model[/bold bright_blue]  {threat_model}\n"
        if input_dir:
            content += f"[bold bright_blue]Input Dir[/bold bright_blue]     {input_dir}\n"
        if output_dir:
            content += f"[bold bright_blue]Output Dir[/bold bright_blue]    {output_dir}\n"
        
        # Add what will be executed
        if mode == "full":
            actions = [
                "• Generate attack trees from project",
                "• Enrich with MITRE ATT&CK mappings",
                "• Add mitigation recommendations"
            ]
        elif mode == "enrich":
            actions = [
                "• Read existing attack trees",
                "• Map to MITRE ATT&CK techniques",
                "• Add tactic information"
            ]
        else:  # mitigate
            actions = [
                "• Read TTC-enriched trees",
                "• Find relevant mitigations",
                "• Add security recommendations"
            ]
        
        content += f"\n[bold bright_blue]This will:[/bold bright_blue]\n"
        for action in actions:
            content += f"{action}\n"
        
        panel = Panel(
            content.rstrip(),
            title="[bold bright_blue]🔍 Review Configuration[/bold bright_blue]",
            border_style="bright_blue",
            box=box.DOUBLE,
            padding=(1, 2)
        )
        self.console.print()
        self.console.print(panel)
        self.console.print()
    
    def print(self, message: str, style: Optional[str] = None):
        """Print message with optional style"""
        if style:
            self.console.print(f"[{style}]{message}[/{style}]")
        else:
            self.console.print(message)
    
    def clear(self):
        """Clear the console"""
        self.console.clear()
