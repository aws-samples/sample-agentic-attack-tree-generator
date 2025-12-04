"""Configuration management utilities"""

import shutil
from pathlib import Path
from typing import Any, Dict

import yaml
from questionary import confirm, select, text
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from threatforest.config import ROOT_DIR


class ConfigManager:
    """Manages ThreatForest configuration"""

    def __init__(self):
        self.console = Console()
        self.user_config_dir = ROOT_DIR / ".threatforest"
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

        self.console.print(
            f"\n[green]✓[/green] Created config: [cyan]{self.user_config_file}[/cyan]"
        )
        self.console.print("\n[dim]Edit this file to customize your ThreatForest settings.[/dim]\n")
        return True

    def show_config(self):
        """Display current configuration"""
        from threatforest.config import config

        # Determine which config is being used
        if (ROOT_DIR / ".threatforest" / "config.yaml").exists():
            config_source = f".threatforest/config.yaml (project config)"
        else:
            config_source = "Bundled default"

        # Detect active provider
        active_provider = "Not configured"
        model_id = "None"

        if config.bedrock and config.bedrock.get("model_id"):
            active_provider = "AWS Bedrock"
            model_id = config.bedrock.get("model_id")
        elif config.anthropic and config.anthropic.get("model_id"):
            active_provider = "Anthropic"
            model_id = config.anthropic.get("model_id")
        elif config.openai and config.openai.get("model_id"):
            active_provider = "OpenAI"
            model_id = config.openai.get("model_id")
        elif config.gemini and config.gemini.get("model_id"):
            active_provider = "Google Gemini"
            model_id = config.gemini.get("model_id")
        elif config.ollama and config.ollama.get("model_id"):
            active_provider = "Ollama"
            model_id = config.ollama.get("model_id")

        # Create table
        table = Table(title="ThreatForest Configuration", show_header=True)
        table.add_column("Setting", style="cyan", width=30)
        table.add_column("Value", style="green")

        # Add rows (no secrets like AWS profile)
        table.add_row("Config Source", config_source)
        table.add_row("Model Provider", active_provider)
        table.add_row("Model ID", model_id)
        table.add_row("Embeddings Model", config.embeddings_model)
        table.add_row("TTP Threshold", str(config.ttc_threshold))

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
            "Anthropic (Experimental)",
            "OpenAI (Experimental)",
            "Google Gemini (Experimental)",
            "Ollama (Experimental)",
            "Keep current",
        ]

        provider_choice = select("Select AI Provider:", choices=providers).ask()

        # Strip experimental flag from provider name
        provider_choice = provider_choice.replace(" (Experimental)", "")

        if provider_choice != "Keep current":
            self.console.print(f"\n[green]✓[/green] Selected: {provider_choice}")

            # Model selection based on provider
            if provider_choice == "AWS Bedrock":
                from threatforest.modules.utils.model_configs import BEDROCK_MODELS, DEFAULT_MODELS

                bedrock_models = BEDROCK_MODELS + ["Other (enter custom model ID)", "Keep current"]
                current_model = config_data.get("bedrock", {}).get(
                    "model_id", DEFAULT_MODELS["bedrock"]
                )
                model_choice = select(
                    f"Select Bedrock Model (current: {current_model}):", choices=bedrock_models
                ).ask()

                if model_choice != "Keep current":
                    # Check if user selected "Other" option
                    if "Other" in model_choice:
                        model_choice = text("Enter custom Bedrock model ID:", default="").ask()

                    if "bedrock" not in config_data:
                        config_data["bedrock"] = {}
                    config_data["bedrock"]["model_id"] = model_choice
                    self.console.print(f"[green]✓[/green] Model: {model_choice}")

            elif provider_choice == "Anthropic":
                from threatforest.modules.utils.model_configs import (
                    ANTHROPIC_MODELS,
                    DEFAULT_MODELS,
                )

                anthropic_models = ANTHROPIC_MODELS + ["Keep current"]
                current_model = config_data.get("anthropic", {}).get(
                    "model_id", DEFAULT_MODELS["anthropic"]
                )
                model_choice = select(
                    f"Select Anthropic Model (current: {current_model}):", choices=anthropic_models
                ).ask()

                if model_choice != "Keep current":
                    if "anthropic" not in config_data:
                        config_data["anthropic"] = {}
                    config_data["anthropic"]["model_id"] = model_choice
                    self.console.print(f"[green]✓[/green] Model: {model_choice}")

            elif provider_choice == "OpenAI":
                from threatforest.modules.utils.model_configs import DEFAULT_MODELS, OPENAI_MODELS

                openai_models = OPENAI_MODELS + ["Keep current"]
                current_model = config_data.get("openai", {}).get(
                    "model_id", DEFAULT_MODELS["openai"]
                )
                model_choice = select(
                    f"Select OpenAI Model (current: {current_model}):", choices=openai_models
                ).ask()

                if model_choice != "Keep current":
                    if "openai" not in config_data:
                        config_data["openai"] = {}
                    config_data["openai"]["model_id"] = model_choice
                    self.console.print(f"[green]✓[/green] Model: {model_choice}")

            elif provider_choice == "Google Gemini":
                from threatforest.modules.utils.model_configs import DEFAULT_MODELS, GEMINI_MODELS

                gemini_models = GEMINI_MODELS + ["Keep current"]
                current_model = config_data.get("gemini", {}).get(
                    "model_id", DEFAULT_MODELS["gemini"]
                )
                model_choice = select(
                    f"Select Gemini Model (current: {current_model}):", choices=gemini_models
                ).ask()

                if model_choice != "Keep current":
                    if "gemini" not in config_data:
                        config_data["gemini"] = {}
                    config_data["gemini"]["model_id"] = model_choice
                    self.console.print(f"[green]✓[/green] Model: {model_choice}")

            elif provider_choice == "Ollama (Local)":
                from threatforest.modules.utils.model_configs import DEFAULT_MODELS

                # For Ollama, allow custom model input
                current_model = config_data.get("ollama", {}).get(
                    "model_id", DEFAULT_MODELS["ollama"]
                )
                model_id = text(
                    f"Enter Ollama Model ID (current: {current_model}):", default=current_model
                ).ask()

                if "ollama" not in config_data:
                    config_data["ollama"] = {}
                config_data["ollama"]["model_id"] = model_id
                self.console.print(f"[green]✓[/green] Model: {model_id}")

        # Save changes
        with open(self.user_config_file, "w") as f:
            yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)

        self.console.print(
            f"\n[green]✓[/green] Config saved: [cyan]{self.user_config_file}[/cyan]\n"
        )

    def set_value(self, key: str, value: str):
        """Set a specific configuration value"""
        if not self.user_config_file.exists():
            self.console.print("[yellow]No user config found. Initializing...[/yellow]")
            self.init_user_config()

        # Load config
        with open(self.user_config_file) as f:
            config_data = yaml.safe_load(f)

        # Parse dot-notation key
        keys = key.split(".")
        current = config_data

        # Navigate to parent
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]

        # Set value
        current[keys[-1]] = value

        # Save
        with open(self.user_config_file, "w") as f:
            yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)

        self.console.print(f"[green]✓[/green] Set [cyan]{key}[/cyan] = [yellow]{value}[/yellow]")

    def get_config_path(self) -> str:
        """Get path to active config file"""
        if self.user_config_file.exists():
            return str(self.user_config_file)
        return str(self.bundled_config)
