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
    
    def check_and_init_config(self) -> bool:
        """Check if config exists, run interactive setup if missing"""
        from threatforest.modules.utils.config_manager import ConfigManager
        manager = ConfigManager()
        
        if not manager.user_config_file.exists():
            # First-time setup wizard
            welcome_panel = Panel(
                "[bold bright_blue]🌳 Welcome to ThreatForest![/bold bright_blue]\n\n"
                "[bright_cyan]It looks like this is your first time here.[/bright_cyan]\n\n"
                "Let's set up your configuration...",
                border_style="bright_blue",
                box=box.DOUBLE,
                padding=(1, 2)
            )
            self.console.print()
            self.console.print(welcome_panel)
            self.console.print()
            
            # Ask: Configure now or skip
            setup_choice = questionary.select(
                "How would you like to proceed?",
                choices=[
                    questionary.Choice("🔧 Configure now (choose provider, model, etc.)", value="configure"),
                    questionary.Choice("⚡ Skip setup (use AWS Bedrock + Claude Sonnet defaults)", value="skip")
                ],
                style=questionary.Style([
                    ('qmark', 'fg:#61afef bold'),
                    ('question', 'bold fg:#e5c07b'),
                    ('pointer', 'fg:#61afef bold'),
                    ('highlighted', 'fg:#61afef bold'),
                ])
            ).ask()
            
            if setup_choice == "skip":
                # Use defaults, no file creation
                self.console.print("\n[green]✓[/green] Using default configuration (AWS Bedrock + Claude Sonnet)")
                self.console.print("[dim]You can customize later by selecting 'Update Configuration'[/dim]\n")
                return False
            
            # Interactive setup
            self.console.print("\n[bold cyan]Let's configure ThreatForest...[/bold cyan]\n")
            
            # 1. Provider selection
            provider = questionary.select(
                "Select your AI provider:",
                choices=[
                    "AWS Bedrock",
                    "Anthropic",
                    "OpenAI",
                    "Google Gemini",
                    "Ollama",
                    "LiteLLM",
                    "LlamaAPI",
                    "AWS SageMaker"
                ]
            ).ask()
            
            # 2. AWS Configuration (if AWS services)
            aws_profile = "default"
            aws_region = "us-east-1"
            if provider in ["AWS Bedrock", "AWS SageMaker"]:
                aws_profile = questionary.text(
                    "AWS Profile name:",
                    default="default"
                ).ask()
                aws_region = questionary.text(
                    "AWS Region:",
                    default="us-east-1"
                ).ask()
            
            # 3. Model/Endpoint selection
            model_id = None
            endpoint_name = None
            ollama_host = None
            
            if provider == "AWS Bedrock":
                # Bedrock: Dropdown with model choices
                from threatforest.modules.utils.model_configs import BEDROCK_MODELS
                
                model_choices = BEDROCK_MODELS + ["Other (enter custom model ID)"]
                model_id = questionary.select(
                    "Select model:",
                    choices=model_choices
                ).ask()
                
                if "Other" in model_id:
                    model_id = questionary.text(
                        "Enter Bedrock model ID:",
                        default=""
                    ).ask()
            
            elif provider == "AWS SageMaker":
                # SageMaker: Ask for endpoint name
                endpoint_name = questionary.text(
                    "SageMaker endpoint name:",
                    default=""
                ).ask()
            
            elif provider == "Ollama":
                # Ollama: Model ID + optional host
                model_id = questionary.text(
                    "Enter Ollama model name:",
                    default="llama3.1"
                ).ask()
                ollama_host = questionary.text(
                    "Ollama host (optional):",
                    default="http://localhost:11434"
                ).ask()
            
            else:
                # All other providers: Just ask for model ID
                model_id = questionary.text(
                    f"Enter {provider} model ID:",
                    default=""
                ).ask()
            
            # Check and setup credentials
            from threatforest.modules.utils.env_manager import EnvManager
            env_manager = EnvManager()
            env_manager.ensure_exists()
            
            # Check for required credentials based on provider
            if provider in ["AWS Bedrock", "AWS SageMaker"]:
                # Check AWS credentials
                current_profile = env_manager.get_value('AWS_PROFILE')
                current_region = env_manager.get_value('AWS_REGION')
                
                if not current_profile or current_profile != aws_profile:
                    env_manager.set_value('AWS_PROFILE', aws_profile)
                if not current_region or current_region != aws_region:
                    env_manager.set_value('AWS_REGION', aws_region)
                
                self.console.print(f"\n[green]✓[/green] AWS credentials configured in .env")
            
            elif provider == "Anthropic":
                if not env_manager.get_value('ANTHROPIC_API_KEY'):
                    self.console.print("\n[yellow]⚠️  ANTHROPIC_API_KEY not found in .env[/yellow]\n")
                    api_key = questionary.password("Enter your Anthropic API key:").ask()
                    if api_key:
                        env_manager.set_value('ANTHROPIC_API_KEY', api_key)
                        self.console.print("[green]✓[/green] API key saved to .env")
            
            elif provider == "OpenAI":
                if not env_manager.get_value('OPENAI_API_KEY'):
                    self.console.print("\n[yellow]⚠️  OPENAI_API_KEY not found in .env[/yellow]\n")
                    api_key = questionary.password("Enter your OpenAI API key:").ask()
                    if api_key:
                        env_manager.set_value('OPENAI_API_KEY', api_key)
                        self.console.print("[green]✓[/green] API key saved to .env")
            
            elif provider == "Google Gemini":
                if not env_manager.get_value('GEMINI_API_KEY'):
                    self.console.print("\n[yellow]⚠️  GEMINI_API_KEY not found in .env[/yellow]\n")
                    api_key = questionary.password("Enter your Gemini API key:").ask()
                    if api_key:
                        env_manager.set_value('GEMINI_API_KEY', api_key)
                        self.console.print("[green]✓[/green] API key saved to .env")
            
            elif provider == "LiteLLM":
                if not env_manager.get_value('LITELLM_API_KEY'):
                    self.console.print("\n[yellow]⚠️  LITELLM_API_KEY not found in .env[/yellow]\n")
                    api_key = questionary.password("Enter your LiteLLM API key:").ask()
                    if api_key:
                        env_manager.set_value('LITELLM_API_KEY', api_key)
                        self.console.print("[green]✓[/green] API key saved to .env")
            
            elif provider == "LlamaAPI":
                if not env_manager.get_value('LLAMAAPI_API_KEY'):
                    self.console.print("\n[yellow]⚠️  LLAMAAPI_API_KEY not found in .env[/yellow]\n")
                    api_key = questionary.password("Enter your LlamaAPI API key:").ask()
                    if api_key:
                        env_manager.set_value('LLAMAAPI_API_KEY', api_key)
                        self.console.print("[green]✓[/green] API key saved to .env")
            
            # Create config with user selections
            import yaml
            config_data = yaml.safe_load(open(manager.bundled_config))
            
            # Remove all provider sections first
            providers_to_remove = ['bedrock', 'anthropic', 'openai', 'gemini', 'ollama', 'litellm', 'llamaapi', 'sagemaker']
            for p in providers_to_remove:
                config_data.pop(p, None)
            
            # Add selected provider configuration
            if provider == "AWS Bedrock":
                config_data['bedrock'] = {'model_id': model_id}
            elif provider == "Anthropic":
                config_data['anthropic'] = {'model_id': model_id}
            elif provider == "OpenAI":
                config_data['openai'] = {'model_id': model_id}
            elif provider == "Google Gemini":
                config_data['gemini'] = {'model_id': model_id}
            elif provider == "Ollama":
                config_data['ollama'] = {
                    'host': ollama_host,
                    'model_id': model_id
                }
            elif provider == "LiteLLM":
                config_data['litellm'] = {'model_id': model_id}
            elif provider == "LlamaAPI":
                config_data['llamaapi'] = {'model_id': model_id}
            elif provider == "AWS SageMaker":
                config_data['sagemaker'] = {'endpoint_name': endpoint_name}
            
            # Save configuration
            manager.user_config_dir.mkdir(parents=True, exist_ok=True)
            with open(manager.user_config_file, 'w') as f:
                yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
            
            # Show confirmation
            self.console.print(f"\n[green]✓[/green] Configuration created at ./.threatforest/config.yaml")
            self.console.print(f"\n[bold cyan]Active Configuration:[/bold cyan]")
            self.console.print(f"  Provider: [yellow]{provider}[/yellow]")
            if model_id:
                self.console.print(f"  Model: [yellow]{model_id}[/yellow]")
            if endpoint_name:
                self.console.print(f"  Endpoint: [yellow]{endpoint_name}[/yellow]")
            if provider in ["AWS Bedrock", "AWS SageMaker"]:
                self.console.print(f"  AWS Profile: [yellow]{aws_profile}[/yellow]")
                self.console.print(f"  AWS Region: [yellow]{aws_region}[/yellow]")
            if ollama_host:
                self.console.print(f"  Host: [yellow]{ollama_host}[/yellow]")
            self.console.print()
            
            return True
        return False
    
    def select_mode(self) -> str:
        """Select workflow mode using questionary with step indicator"""
        # Show step header
        self._show_step_indicator(1, 4, "Select Workflow Mode")
        
        mode = questionary.select(
            "Choose your workflow:",
            choices=[
                questionary.Choice("🚀 Full Workflow (Generate + Enrich + Mitigate)", value="full"),
                questionary.Choice("🔍 TTC Enrichment Only", value="enrich"),
                questionary.Choice("🛡️  Mitigation Mapping Only", value="mitigate"),
                questionary.Choice("⚙️  Update Configuration", value="settings")
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
