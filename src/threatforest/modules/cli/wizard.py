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
        """Check if config.yaml AND .env exist, run interactive setup if either missing"""
        from threatforest.modules.utils.config_manager import ConfigManager
        from threatforest.modules.utils.env_manager import EnvManager
        
        manager = ConfigManager()
        env_manager = EnvManager()
        
        config_missing = not manager.user_config_file.exists()
        env_missing = not env_manager.env_file.exists()
        
        if config_missing or env_missing:
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
                    "Anthropic (Experimental)",
                    "OpenAI (Experimental)",
                    "Google Gemini (Experimental)",
                    "Ollama (Experimental)",
                    "LiteLLM (Experimental)",
                    "LlamaAPI (Experimental)"
                ]
            ).ask()
            
            # Strip experimental flag from provider name for internal use
            provider = provider.replace(" (Experimental)", "")
            
            # 2. Model/Endpoint selection
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
                # Ask user to choose auth method
                auth_choice = questionary.select(
                    "How do you want to authenticate with AWS?",
                    choices=[
                        questionary.Choice("🔑 AWS Profile (recommended)", value="profile"),
                        questionary.Choice("🔐 Access Keys", value="access_keys")
                    ]
                ).ask()
                
                if auth_choice == "profile":
                    aws_profile = questionary.text(
                        "AWS Profile name:",
                        default="default"
                    ).ask()
                    
                    aws_region = questionary.text(
                        "AWS Region:",
                        default="us-east-1"
                    ).ask()
                    
                    env_manager.set_value('AWS_PROFILE', aws_profile)
                    env_manager.set_value('AWS_REGION', aws_region)
                    
                    self.console.print(f"\n[green]✓[/green] AWS Profile configured: {aws_profile}")
                    self.console.print(f"[green]✓[/green] AWS Region configured: {aws_region}")
                    
                    # Test AWS connection
                    self.console.print("\n[cyan]Testing AWS connection...[/cyan]")
                    from threatforest.modules.utils.aws_validator import test_aws_connection
                    result = test_aws_connection(profile=aws_profile, region=aws_region)
                    
                    if not result['success']:
                        # Ask if user wants to reconfigure
                        retry = questionary.confirm(
                            "Would you like to reconfigure AWS credentials?",
                            default=True
                        ).ask()
                        if retry:
                            # Clear the invalid credentials
                            env_manager.set_value('AWS_PROFILE', '')
                            env_manager.set_value('AWS_REGION', '')
                            self.console.print("[yellow]Credentials cleared. Please restart setup.[/yellow]\n")
                            return False
                
                else:  # access_keys
                    access_key_id = questionary.password("AWS Access Key ID:").ask()
                    secret_access_key = questionary.password("AWS Secret Access Key:").ask()
                    
                    aws_region = questionary.text(
                        "AWS Region:",
                        default="us-east-1"
                    ).ask()
                    
                    env_manager.set_value('AWS_ACCESS_KEY_ID', access_key_id)
                    env_manager.set_value('AWS_SECRET_ACCESS_KEY', secret_access_key)
                    env_manager.set_value('AWS_REGION', aws_region)
                    
                    self.console.print(f"\n[green]✓[/green] AWS Access Keys configured")
                    self.console.print(f"[green]✓[/green] AWS Region configured: {aws_region}")
                    
                    # Test AWS connection
                    self.console.print("\n[cyan]Testing AWS connection...[/cyan]")
                    from threatforest.modules.utils.aws_validator import test_aws_connection
                    result = test_aws_connection(
                        access_key_id=access_key_id,
                        secret_access_key=secret_access_key,
                        region=aws_region
                    )
                    
                    if not result['success']:
                        # Ask if user wants to reconfigure
                        retry = questionary.confirm(
                            "Would you like to reconfigure AWS credentials?",
                            default=True
                        ).ask()
                        if retry:
                            # Clear the invalid credentials
                            env_manager.set_value('AWS_ACCESS_KEY_ID', '')
                            env_manager.set_value('AWS_SECRET_ACCESS_KEY', '')
                            env_manager.set_value('AWS_REGION', '')
                            self.console.print("[yellow]Credentials cleared. Please restart setup.[/yellow]\n")
                            return False
            
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
                # Show auth method that was configured
                if env_manager.get_value('AWS_PROFILE'):
                    profile = env_manager.get_value('AWS_PROFILE')
                    self.console.print(f"  Auth: [yellow]Profile ({profile})[/yellow]")
                elif env_manager.get_value('AWS_ACCESS_KEY_ID'):
                    self.console.print(f"  Auth: [yellow]Access Keys[/yellow]")
                region = env_manager.get_value('AWS_REGION') or 'us-east-1'
                self.console.print(f"  Region: [yellow]{region}[/yellow]")
            if ollama_host:
                self.console.print(f"  Host: [yellow]{ollama_host}[/yellow]")
            self.console.print()
            
            return True
        return False
    
    def select_mode(self) -> str:
        """Select workflow mode using questionary with step indicator"""
        # Show step header
        self._show_step_indicator(1, 4, "Select Action")
        
        mode = questionary.select(
            "What would you like to do?",
            choices=[
                questionary.Choice("🌳 Generate Attack Trees & Analysis", value="full"),
                questionary.Choice("─────────────", value="separator", disabled=True),
                questionary.Choice("🔑 Update Credentials (returns to menu)", value="credentials"),
                questionary.Choice("⚙️  Configure Model Settings (returns to menu)", value="model_settings"),
                questionary.Choice("🚪 Exit Application", value="exit")
            ],
            style=questionary.Style([
                ('qmark', 'fg:#61afef bold'),  # Blue
                ('question', 'bold fg:#e5c07b'),  # Yellow
                ('answer', 'fg:#98c379 bold'),  # Green
                ('pointer', 'fg:#61afef bold'),  # Blue
                ('highlighted', 'fg:#61afef bold'),  # Blue
                ('selected', 'fg:#98c379'),  # Green
                ('disabled', 'fg:#5c6370'),  # Gray for separator
            ])
        ).ask()
        
        return mode if mode else "exit"
    
    def get_project_path(self) -> str:
        """Get project path from user with validation"""
        self._show_step_indicator(2, 4, "Select Project Directory")
        self.console.print("[dim]📂 Choose the directory where your application information is stored[/dim]")
        self.console.print("[dim]   (README, architecture diagrams, dataflow diagrams, etc.)[/dim]\n")
        
        while True:
            path_str = questionary.path(
                "Project directory path:",
                default="",
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
    
    def ask_threat_statement_preference(self) -> tuple[bool, Optional[str]]:
        """Ask if user has existing threat statements
        
        Returns:
            Tuple of (has_threats, threat_file_path)
            - has_threats: True if user has existing threats
            - threat_file_path: Path to threat file if provided, None otherwise
        """
        self._show_step_indicator(3, 4, "Threat Statements")
        
        info_panel = Panel(
            "[bold blue]📋 Threat Statements[/bold blue]\n\n"
            "[dim]Do you have existing threat statements for this project?[/dim]\n"
            "[dim]If not, we'll generate them automatically using AI analysis.[/dim]",
            border_style="blue",
            box=box.ROUNDED,
            padding=(1, 2)
        )
        self.console.print(info_panel)
        self.console.print()
        
        has_threats = Confirm.ask(
            "[bold]Do you have existing threat statements?[/bold]",
            default=False
        )
        
        if not has_threats:
            self.console.print("[cyan]✓[/cyan] Threat statements will be auto-generated\n")
            return False, None
        
        # User has threats, ask for file path
        self.console.print("[dim]Please provide the path to your threat statements file[/dim]")
        self.console.print("[dim]Supported formats: JSON, YAML, Markdown, ThreatComposer (.tc.json)[/dim]\n")
        
        while True:
            path_str = questionary.path(
                "Threat statements file path:",
                default="",
                only_directories=False,
                style=questionary.Style([
                    ('qmark', 'fg:#61afef bold'),
                    ('question', 'bold fg:#e5c07b'),
                    ('answer', 'fg:#98c379 bold'),
                ])
            ).ask()
            
            if path_str is None:
                # User cancelled
                self.console.print("[yellow]⚠️  No file provided, will auto-generate threats[/yellow]\n")
                return False, None
            
            if not path_str:
                # Empty string, ask again
                self.console.print("[yellow]Please provide a file path or press Ctrl+C to skip[/yellow]\n")
                continue
            
            threat_path = Path(path_str).expanduser().resolve()
            
            if threat_path.exists() and threat_path.is_file():
                self.console.print(f"[bright_green]✓[/bright_green] Using threat file: [cyan]{threat_path}[/cyan]\n")
                return True, str(threat_path)
            else:
                error_panel = Panel(
                    f"[red]File not found:[/red] [yellow]{threat_path}[/yellow]\n\n"
                    "[dim]💡 Tip: Use tab for autocomplete[/dim]",
                    border_style="red",
                    box=box.ROUNDED,
                    padding=(1, 2)
                )
                self.console.print(error_panel)
                self.console.print()
    
    def get_threat_model_path(self) -> Optional[str]:
        """Get optional threat model path with validation
        
        DEPRECATED: Use ask_threat_statement_preference instead.
        This method is kept for backward compatibility.
        """
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
        if mode == "full":
            info_text = """[bold bright_blue]🌳 Attack Tree Generation & Analysis[/bold bright_blue]

This will execute a complete security analysis:
  [cyan]1.[/cyan] Analyze project and extract security context
  [cyan]2.[/cyan] Generate comprehensive attack trees
  [cyan]3.[/cyan] Enrich with MITRE ATT&CK TTP mappings
  [cyan]4.[/cyan] Add mitigation recommendations

[dim]Estimated time: 5-15 minutes depending on project size[/dim]"""
            
            panel = Panel(
                info_text.strip(),
                border_style="bright_blue",
                box=box.DOUBLE,
                padding=(1, 2)
            )
            self.console.print()
            self.console.print(panel)
            self.console.print()
    
    def update_credentials(self):
        """Update credentials - let user select which provider to configure"""
        from threatforest.modules.utils.env_manager import EnvManager
        
        env_manager = EnvManager()
        env_manager.ensure_exists()
        
        self.console.print("\n[bold cyan]Select provider to configure:[/bold cyan]\n")
        
        # Build provider choices with status indicators
        choices = []
        
        # AWS Bedrock
        if env_manager.get_value('AWS_PROFILE'):
            profile = env_manager.get_value('AWS_PROFILE')
            choices.append(questionary.Choice(f"✓ AWS Bedrock [Profile: {profile}]", value="AWS Bedrock"))
        elif env_manager.get_value('AWS_ACCESS_KEY_ID'):
            choices.append(questionary.Choice(f"✓ AWS Bedrock [Access Keys]", value="AWS Bedrock"))
        else:
            choices.append(questionary.Choice(f"○ AWS Bedrock [Not configured]", value="AWS Bedrock"))
        
        # Anthropic (Experimental)
        if env_manager.get_value('ANTHROPIC_API_KEY'):
            choices.append(questionary.Choice(f"✓ Anthropic (Experimental) [API Key configured]", value="Anthropic"))
        else:
            choices.append(questionary.Choice(f"○ Anthropic (Experimental) [Not configured]", value="Anthropic"))
        
        # OpenAI (Experimental)
        if env_manager.get_value('OPENAI_API_KEY'):
            choices.append(questionary.Choice(f"✓ OpenAI (Experimental) [API Key configured]", value="OpenAI"))
        else:
            choices.append(questionary.Choice(f"○ OpenAI (Experimental) [Not configured]", value="OpenAI"))
        
        # Google Gemini (Experimental)
        if env_manager.get_value('GEMINI_API_KEY'):
            choices.append(questionary.Choice(f"✓ Google Gemini (Experimental) [API Key configured]", value="Google Gemini"))
        else:
            choices.append(questionary.Choice(f"○ Google Gemini (Experimental) [Not configured]", value="Google Gemini"))
        
        # LiteLLM (Experimental)
        if env_manager.get_value('LITELLM_API_KEY'):
            choices.append(questionary.Choice(f"✓ LiteLLM (Experimental) [API Key configured]", value="LiteLLM"))
        else:
            choices.append(questionary.Choice(f"○ LiteLLM (Experimental) [Not configured]", value="LiteLLM"))
        
        # LlamaAPI (Experimental)
        if env_manager.get_value('LLAMAAPI_API_KEY'):
            choices.append(questionary.Choice(f"✓ LlamaAPI (Experimental) [API Key configured]", value="LlamaAPI"))
        else:
            choices.append(questionary.Choice(f"○ LlamaAPI (Experimental) [Not configured]", value="LlamaAPI"))
        
        # Ollama (Experimental, no credentials)
        choices.append(questionary.Choice(f"✓ Ollama (Experimental) [No credentials needed]", value="Ollama"))
        
        # Add cancel option
        choices.append(questionary.Choice(f"← Cancel", value="cancel"))
        
        # Let user select provider
        provider = questionary.select(
            "Select provider:",
            choices=choices,
            style=questionary.Style([
                ('qmark', 'fg:#61afef bold'),
                ('question', 'bold fg:#e5c07b'),
                ('pointer', 'fg:#61afef bold'),
                ('highlighted', 'fg:#61afef bold'),
            ])
        ).ask()
        
        if not provider or provider == "cancel":
            self.console.print("\n[dim]Cancelled credential update[/dim]\n")
            return False
        
        self.console.print(f"\n[bold cyan]Configuring: {provider}[/bold cyan]\n")
        
        # AWS providers
        if provider in ["AWS Bedrock", "AWS SageMaker"]:
            auth_choice = questionary.select(
                "How do you want to authenticate with AWS?",
                choices=[
                    questionary.Choice("🔑 AWS Profile (recommended)", value="profile"),
                    questionary.Choice("🔐 Access Keys", value="access_keys")
                ]
            ).ask()
            
            if auth_choice == "profile":
                current_profile = env_manager.get_value('AWS_PROFILE') or 'default'
                profile = questionary.text(
                    f"AWS Profile name (current: {current_profile}):",
                    default=current_profile
                ).ask()
                
                current_region = env_manager.get_value('AWS_REGION') or 'us-east-1'
                region = questionary.text(
                    f"AWS Region (current: {current_region}):",
                    default=current_region
                ).ask()
                
                env_manager.set_value('AWS_PROFILE', profile)
                env_manager.set_value('AWS_REGION', region)
                
                # Remove access keys if they exist
                if env_manager.get_value('AWS_ACCESS_KEY_ID'):
                    env_manager.set_value('AWS_ACCESS_KEY_ID', '')
                if env_manager.get_value('AWS_SECRET_ACCESS_KEY'):
                    env_manager.set_value('AWS_SECRET_ACCESS_KEY', '')
                
                self.console.print(f"\n[green]✓[/green] AWS Profile configured: {profile}")
                self.console.print(f"[green]✓[/green] AWS Region configured: {region}")
                
                # Test AWS connection
                self.console.print("\n[cyan]Testing AWS connection...[/cyan]")
                from threatforest.modules.utils.aws_validator import test_aws_connection
                result = test_aws_connection(profile=profile, region=region)
                
                if not result['success']:
                    # Ask if user wants to retry
                    retry = questionary.confirm(
                        "Connection failed. Would you like to try different credentials?",
                        default=True
                    ).ask()
                    if not retry:
                        self.console.print("\n[yellow]⚠️  Credentials saved but connection test failed[/yellow]")
                        self.console.print("[dim]You may need to fix them before using ThreatForest[/dim]\n")
            
            else:  # access_keys
                access_key_id = questionary.password("AWS Access Key ID:").ask()
                secret_access_key = questionary.password("AWS Secret Access Key:").ask()
                
                current_region = env_manager.get_value('AWS_REGION') or 'us-east-1'
                region = questionary.text(
                    f"AWS Region (current: {current_region}):",
                    default=current_region
                ).ask()
                
                env_manager.set_value('AWS_ACCESS_KEY_ID', access_key_id)
                env_manager.set_value('AWS_SECRET_ACCESS_KEY', secret_access_key)
                env_manager.set_value('AWS_REGION', region)
                
                # Remove profile if it exists
                if env_manager.get_value('AWS_PROFILE'):
                    env_manager.set_value('AWS_PROFILE', '')
                
                self.console.print(f"\n[green]✓[/green] AWS Access Keys configured")
                self.console.print(f"[green]✓[/green] AWS Region configured: {region}")
                
                # Test AWS connection
                self.console.print("\n[cyan]Testing AWS connection...[/cyan]")
                from threatforest.modules.utils.aws_validator import test_aws_connection
                result = test_aws_connection(
                    access_key_id=access_key_id,
                    secret_access_key=secret_access_key,
                    region=region
                )
                
                if not result['success']:
                    # Ask if user wants to retry
                    retry = questionary.confirm(
                        "Connection failed. Would you like to try different credentials?",
                        default=True
                    ).ask()
                    if not retry:
                        self.console.print("\n[yellow]⚠️  Credentials saved but connection test failed[/yellow]")
                        self.console.print("[dim]You may need to fix them before using ThreatForest[/dim]\n")
        
        # API Key providers
        elif provider in ["Anthropic", "OpenAI", "Google Gemini", "LiteLLM", "LlamaAPI"]:
            key_var_map = {
                "Anthropic": "ANTHROPIC_API_KEY",
                "OpenAI": "OPENAI_API_KEY",
                "Google Gemini": "GEMINI_API_KEY",
                "LiteLLM": "LITELLM_API_KEY",
                "LlamaAPI": "LLAMAAPI_API_KEY"
            }
            
            key_var = key_var_map.get(provider)
            if key_var:
                api_key = questionary.password(f"Enter {provider} API key:").ask()
                if api_key:
                    env_manager.set_value(key_var, api_key)
                    self.console.print(f"\n[green]✓[/green] {provider} API key configured")
        
        # Ollama - no credentials needed
        elif provider == "Ollama":
            self.console.print("\n[dim]Ollama runs locally and doesn't require credentials[/dim]")
            self.console.print("[dim]If you need to change the host, use 'Configure Model Settings'[/dim]")
        
        self.console.print("\n[green]✓[/green] Credentials updated successfully!")
        self.console.print("[dim]Changes will take effect immediately[/dim]\n")
        
        return True
    
    def configure_model_settings(self):
        """Configure model settings (provider/model selection) - doesn't exit CLI"""
        from threatforest.modules.utils.config_manager import ConfigManager
        
        manager = ConfigManager()
        
        if not manager.user_config_file.exists():
            manager.init_user_config()
        
        # Use the existing edit_interactive from ConfigManager
        # But we need to refactor it to not handle credentials
        manager.edit_interactive()
        
        self.console.print("\n[green]✓[/green] Model settings updated!")
        self.console.print("[dim]Restart ThreatForest to use new model configuration[/dim]\n")
        
        return True
    
    def ask_open_docs(self) -> bool:
        """Ask user if they want to open the attack trees documentation now.
        
        Returns:
            True if user wants to open docs, False otherwise
        """
        self.console.print()
        
        info_panel = Panel(
            "[bold cyan]📚 Documentation Generation[/bold cyan]\n\n"
            "[dim]Would you like to generate and open the attack trees documentation now?[/dim]\n\n"
            "[bright_green]✓[/bright_green] Generates a navigable MkDocs site\n"
            "[bright_green]✓[/bright_green] Opens automatically in your browser\n"
            "[bright_green]✓[/bright_green] Includes all attack trees and threat statements",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(1, 2)
        )
        self.console.print(info_panel)
        self.console.print()
        
        choice = questionary.select(
            "Do you want to open the attack trees now?",
            choices=[
                questionary.Choice("✓ Yes, generate and open documentation", value=True),
                questionary.Choice("✗ No, I'll do it manually later", value=False)
            ],
            style=questionary.Style([
                ('qmark', 'fg:#61afef bold'),
                ('question', 'bold fg:#e5c07b'),
                ('pointer', 'fg:#61afef bold'),
                ('highlighted', 'fg:#61afef bold'),
            ])
        ).ask()
        
        return choice
    
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
