"""Interactive wizard for ThreatForest CLI"""
from pathlib import Path
from typing import Optional, Dict, Any
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich import box
import questionary


class CLIWizard:
    """Interactive configuration wizard"""
    
    def __init__(self):
        self.console = Console()
    
    def select_mode(self) -> str:
        """Select workflow mode using questionary with step indicator"""
        # Show step header
        self._show_step_indicator(1, 4, "Select Workflow Mode")
        
        mode = questionary.select(
            "Choose your workflow:",
            choices=[
                questionary.Choice("🚀 Full Workflow (Generate + Enrich + Mitigate)", value="full"),
                questionary.Choice("🔍 TTC Enrichment Only", value="enrich"),
                questionary.Choice("🛡️  Mitigation Mapping Only", value="mitigate")
            ],
            style=questionary.Style([
                ('qmark', 'fg:#61afef bold'),  # Blue
                ('question', 'bold fg:#e5c07b'),  # Yellow
                ('answer', 'fg:#98c379 bold'),  # Green
                ('pointer', 'fg:#61afef bold'),  # Blue
                ('highlighted', 'fg:#61afef bold'),  # Blue
                ('selected', 'fg:#98c379'),  # Green
            ])
        ).ask()
        
        return mode if mode else "full"
    
    def get_project_path(self) -> str:
        """Get project path from user with validation"""
        self._show_step_indicator(2, 4, "Select Project Directory")
        self.console.print("[dim]📂 Choose the project directory to analyze[/dim]\n")
        
        while True:
            path_str = questionary.path(
                "Project directory path:",
                default="./",
                only_directories=True,
                style=questionary.Style([
                    ('qmark', 'fg:#61afef bold'),
                    ('question', 'bold fg:#e5c07b'),
                    ('answer', 'fg:#98c379 bold'),
                ])
            ).ask()
            
            if path_str is None:
                # User cancelled
                raise KeyboardInterrupt()
            
            project_path = Path(path_str).expanduser().resolve()
            
            if project_path.exists() and project_path.is_dir():
                self.console.print(f"[bright_green]✓[/bright_green] Valid directory: [cyan]{project_path}[/cyan]\n")
                return str(project_path)
            else:
                error_panel = Panel(
                    f"[red]Directory not found:[/red] [yellow]{project_path}[/yellow]\n\n"
                    "[dim]💡 Tip: Use tab for autocomplete[/dim]",
                    border_style="red",
                    box=box.ROUNDED,
                    padding=(1, 2)
                )
                self.console.print(error_panel)
                self.console.print()
    
    def get_threat_model_path(self) -> Optional[str]:
        """Get optional threat model path with validation"""
        self._show_step_indicator(3, 4, "Threat Model (Optional)")
        
        info_panel = Panel(
            "[bold blue]📄 Threat Model Document[/bold blue]\n\n"
            "[dim]Recommended: Use Threat Composer export file[/dim]\n"
            "[dim]URL: https://awslabs.github.io/threat-composer/[/dim]\n\n"
            "[dim]Press Enter to skip[/dim]",
            border_style="blue",
            box=box.ROUNDED,
            padding=(1, 2)
        )
        self.console.print(info_panel)
        self.console.print()
        
        path_str = Prompt.ask(
            "[bold]Threat model file path[/bold]",
            default=""
        )
        
        if not path_str:
            self.console.print("[dim]⊘ Skipping threat model[/dim]\n")
            return None
        
        threat_path = Path(path_str).expanduser().resolve()
        
        if threat_path.exists() and threat_path.is_file():
            self.console.print(f"[bright_green]✓[/bright_green] Using threat model: [cyan]{threat_path}[/cyan]\n")
            return str(threat_path)
        else:
            warning_panel = Panel(
                f"[yellow]⚠️  File not found:[/yellow] [dim]{threat_path}[/dim]\n\n"
                "[dim]Continuing without threat model...[/dim]",
                border_style="yellow",
                box=box.ROUNDED,
                padding=(1, 2)
            )
            self.console.print(warning_panel)
            self.console.print()
            return None
    
    def get_input_output_dirs(self, mode: str) -> tuple[str, str]:
        """Get input and output directories for enrich/mitigate modes"""
        self._show_step_indicator(2, 3, "Configure Directories")
        
        if mode == "enrich":
            title = "TTC Enrichment Paths"
            default_input = "./output/attack_trees"
            default_output = "./output/enriched"
        else:  # mitigate
            title = "Mitigation Mapping Paths"
            default_input = "./output/enriched"
            default_output = "./output/mitigated"
        
        info_panel = Panel(
            f"[bold blue]{title}[/bold blue]\n\n"
            "[dim]Specify input and output directories[/dim]",
            border_style="blue",
            box=box.ROUNDED,
            padding=(1, 2)
        )
        self.console.print(info_panel)
        self.console.print()
        
        input_dir = Prompt.ask(
            "[bold]📥 Input directory[/bold]",
            default=default_input
        )
        self.console.print(f"[bright_green]✓[/bright_green] Input: [cyan]{input_dir}[/cyan]\n")
        
        output_dir = Prompt.ask(
            "[bold]📤 Output directory[/bold]",
            default=default_output
        )
        self.console.print(f"[bright_green]✓[/bright_green] Output: [cyan]{output_dir}[/cyan]\n")
        
        return input_dir, output_dir
    
    def confirm_continue(self, message: str) -> bool:
        """Ask user for confirmation"""
        self.console.print()
        return Confirm.ask(message, default=True)
    
    def show_mode_info(self, mode: str):
        """Display information about selected mode with icons"""
        info_text = {
            "full": """[bold bright_blue]🚀 Full Workflow[/bold bright_blue]

This will execute all three stages:
  [cyan]1.[/cyan] Generate attack trees from threat model
  [cyan]2.[/cyan] Enrich with TTC (MITRE ATT&CK) mappings
  [cyan]3.[/cyan] Add mitigation recommendations

[dim]Estimated time: 5-15 minutes depending on project size[/dim]""",
            
            "enrich": """[bold bright_blue]🔍 TTC Enrichment[/bold bright_blue]

This workflow will:
  [cyan]•[/cyan] Read existing attack trees
  [cyan]•[/cyan] Map attack steps to MITRE ATT&CK techniques
  [cyan]•[/cyan] Add tactic and technique information

[dim]Input: Attack tree JSON files
Output: Enriched trees with TTC mappings[/dim]""",
            
            "mitigate": """[bold bright_blue]🛡️  Mitigation Mapping[/bold bright_blue]

This workflow will:
  [cyan]•[/cyan] Read TTC-enriched attack trees
  [cyan]•[/cyan] Find relevant mitigation strategies
  [cyan]•[/cyan] Add actionable security recommendations

[dim]Input: TTC-enriched attack trees
Output: Trees with mitigation mappings[/dim]"""
        }
        
        if mode in info_text:
            panel = Panel(
                info_text[mode].strip(),
                border_style="bright_blue",
                box=box.DOUBLE,
                padding=(1, 2)
            )
            self.console.print()
            self.console.print(panel)
            self.console.print()
    
    def _show_step_indicator(self, current: int, total: int, title: str):
        """Show step progress indicator"""
        progress_bar = ""
        for i in range(1, total + 1):
            if i < current:
                progress_bar += "[bright_green]●[/bright_green] "
            elif i == current:
                progress_bar += "[bright_blue]●[/bright_blue] "
            else:
                progress_bar += "[dim]○[/dim] "
        
        header = Panel(
            f"{progress_bar}\n\n[bold bright_blue]Step {current}/{total}:[/bold bright_blue] [bold]{title}[/bold]",
            border_style="bright_blue",
            box=box.ROUNDED,
            padding=(1, 2)
        )
        self.console.print()
        self.console.print(header)
