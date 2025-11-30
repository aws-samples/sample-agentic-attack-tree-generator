"""Configuration management utilities"""
import yaml
import shutil
from pathlib import Path
from typing import Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from questionary import select, text, confirm


class ConfigManager:
    """Manages ThreatForest configuration"""
    
    def __init__(self):
        self.console = Console()
        self.user_config_dir = Path.cwd() / ".threatforest"
        self.user_config_file = self.user_config_dir / "config.yaml"
        self.bundled_config = Path(__file__).parent.parent.parent / "config.yaml"
    
    def init_user_config(self, force: bool = False) -> bool:
        """Initialize user config from bundled default"""
        if self.user_config_file.exists() and not force:
            self.console.print(f"[yellow]Config already exists:[/yellow] {self.user_config_file}")
            if not confirm("Overwrite existing config?", default=False).ask():
                return False
        
        # Create directory if needed
        self.user_config_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy bundled config
        shutil.copy(self.bundled_config, self.user_config_file)
        
        self.console.print(f"\n[green]✓[/green] Created config: [cyan]{self.user_config_file}[/cyan]")
        self.console.print("\n[dim]Edit this file to customize your ThreatForest settings.[/dim]\n")
        return True
    
    def show_config(self):
        """Display current configuration"""
        from threatforest.config import config
        
        # Determine which config is being used
        if (Path.cwd() / "config.yaml").exists():
            config_source = f"{Path.cwd()}/config.yaml (project override)"
        elif self.user_config_file.exists():
            config_source = f"~/.threatforest/config.yaml (user config)"
        else:
            config_source = "Bundled default"
        
        # Create table
        table = Table(title="ThreatForest Configuration", show_header=True)
        table.add_column("Setting", style="cyan", width=30)
        table.add_column("Value", style="green")
        
        # Add rows
        table.add_row("Config Source", config_source)
        table.add_row("Model", config.default_bedrock_model)
        table.add_row("Embeddings Model", config.embeddings_model)
        table.add_row("TTC Threshold", str(config.ttc_threshold))
        table.add_row("AWS Profile", config.default_aws_profile)
        table.add_row("AWS Region", config.default_aws_region)
        
        self.console.print()
        self.console.print(table)
        self.console.print()
    
    def edit_interactive(self):
        """Interactive configuration editor"""
        if not self.user_config_file.exists():
            self.console.print("[yellow]No user config found. Initializing...[/yellow]")
            self.init_user_config()
        
        # Load current config
        with open(self.user_config_file) as f:
            config_data = yaml.safe_load(f)
        
        self.console.print("\n[bold cyan]Interactive Configuration Editor[/bold cyan]\n")
        
        # Provider selection
        providers = [
            "AWS Bedrock",
            "Anthropic",
            "OpenAI",
            "Google Gemini",
            "Ollama (Local)",
            "Keep current"
        ]
        
        provider_choice = select(
            "Select AI Provider:",
            choices=providers
        ).ask()
        
        if provider_choice != "Keep current":
            self.console.print(f"\n[green]✓[/green] Selected: {provider_choice}")
            # Would implement provider-specific config here
        
        # AWS Profile (if using AWS services)
        if provider_choice in ["AWS Bedrock", "Keep current"]:
            current_profile = config_data.get('aws', {}).get('default_profile', 'default')
            new_profile = text(
                f"AWS Profile (current: {current_profile}):",
                default=current_profile
            ).ask()
            
            if 'aws' not in config_data:
                config_data['aws'] = {}
            config_data['aws']['default_profile'] = new_profile
        
        # Save changes
        with open(self.user_config_file, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
        
        self.console.print(f"\n[green]✓[/green] Config saved: [cyan]{self.user_config_file}[/cyan]\n")
    
    def set_value(self, key: str, value: str):
        """Set a specific configuration value"""
        if not self.user_config_file.exists():
            self.console.print("[yellow]No user config found. Initializing...[/yellow]")
            self.init_user_config()
        
        # Load config
        with open(self.user_config_file) as f:
            config_data = yaml.safe_load(f)
        
        # Parse dot-notation key
        keys = key.split('.')
        current = config_data
        
        # Navigate to parent
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        # Set value
        current[keys[-1]] = value
        
        # Save
        with open(self.user_config_file, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
        
        self.console.print(f"[green]✓[/green] Set [cyan]{key}[/cyan] = [yellow]{value}[/yellow]")
    
    def get_config_path(self) -> str:
        """Get path to active config file"""
        if self.user_config_file.exists():
            return str(self.user_config_file)
        return str(self.bundled_config)
