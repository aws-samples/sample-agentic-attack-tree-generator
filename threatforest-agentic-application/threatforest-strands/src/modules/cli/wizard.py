"""Interactive wizard for ThreatForest CLI"""
from pathlib import Path
from typing import Optional, Dict, Any
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
import questionary


class CLIWizard:
    """Interactive configuration wizard"""
    
    def __init__(self):
        self.console = Console()
    
    def select_mode(self) -> str:
        """Select workflow mode using questionary"""
        self.console.print()
        
        mode = questionary.select(
            "Select Workflow Mode:",
            choices=[
                questionary.Choice("Full Workflow (Generate + Enrich + Mitigate)", value="full"),
                questionary.Choice("TTC Enrichment Only", value="enrich"),
                questionary.Choice("Mitigation Mapping Only", value="mitigate")
            ],
            style=questionary.Style([
                ('qmark', 'fg:cyan bold'),
                ('question', 'bold'),
                ('answer', 'fg:cyan bold'),
                ('pointer', 'fg:cyan bold'),
                ('highlighted', 'fg:cyan bold'),
                ('selected', 'fg:green'),
            ])
        ).ask()
        
        return mode if mode else "full"
    
    def get_project_path(self) -> str:
        """Get project path from user"""
        self.console.print()
        
        while True:
            path_str = questionary.path(
                "Enter project directory path:",
                default="",
                only_directories=True
            ).ask()
            
            if path_str is None:
                # User cancelled
                raise KeyboardInterrupt()
            
            project_path = Path(path_str).expanduser().resolve()
            
            if project_path.exists() and project_path.is_dir():
                return str(project_path)
            else:
                self.console.print(f"[red]✗[/red] Directory not found: {project_path}")
                self.console.print()
    
    def get_threat_model_path(self) -> Optional[str]:
        """Get optional threat model path"""
        self.console.print()
        self.console.print("[dim]Threat Model Document (optional)[/dim]")
        self.console.print("[dim]Recommended: Use Threat Composer export file[/dim]")
        self.console.print("[dim]URL: https://awslabs.github.io/threat-composer/[/dim]")
        self.console.print()
        
        path_str = Prompt.ask(
            "Enter threat model file path",
            default=""
        )
        
        if not path_str:
            return None
        
        threat_path = Path(path_str).expanduser().resolve()
        
        if threat_path.exists() and threat_path.is_file():
            return str(threat_path)
        else:
            self.console.print(f"[yellow]⚠[/yellow] File not found: {threat_path}")
            self.console.print("[yellow]Continuing without threat model...[/yellow]")
            return None
    
    def get_input_output_dirs(self, mode: str) -> tuple[str, str]:
        """Get input and output directories for enrich/mitigate modes"""
        if mode == "enrich":
            self.console.print("[bold cyan]TTC Enrichment Paths[/bold cyan]")
            default_input = "./output/attack_trees"
            default_output = "./output/enriched"
        else:  # mitigate
            self.console.print("[bold cyan]Mitigation Mapping Paths[/bold cyan]")
            default_input = "./output/enriched"
            default_output = "./output/mitigated"
        
        input_dir = Prompt.ask(
            "Input directory",
            default=default_input
        )
        
        output_dir = Prompt.ask(
            "Output directory",
            default=default_output
        )
        
        return input_dir, output_dir
    
    def confirm_continue(self, message: str) -> bool:
        """Ask user for confirmation"""
        self.console.print()
        return Confirm.ask(message, default=True)
    
    def show_mode_info(self, mode: str):
        """Display information about selected mode"""
        info_text = {
            "full": """
[bold]Full Workflow[/bold] will execute all three stages:
  1. Generate attack trees from threat model
  2. Enrich with TTC (MITRE ATT&CK) mappings
  3. Add mitigation recommendations
            """,
            "enrich": """
[bold]TTC Enrichment[/bold] will:
  - Read existing attack trees
  - Map attack steps to MITRE ATT&CK techniques
  - Add tactic and technique information
            """,
            "mitigate": """
[bold]Mitigation Mapping[/bold] will:
  - Read TTC-enriched attack trees
  - Find relevant mitigation strategies
  - Add actionable security recommendations
            """
        }
        
        if mode in info_text:
            panel = Panel(
                info_text[mode].strip(),
                border_style="blue",
                padding=(1, 2)
            )
            self.console.print(panel)
            self.console.print()
