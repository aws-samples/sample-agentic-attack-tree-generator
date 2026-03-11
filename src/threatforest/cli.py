#!/usr/bin/env python3
"""
ThreatForest Python CLI
Main command-line interface using Rich for display
"""
import os

# Suppress tokenizers parallelism warning
os.environ["TOKENIZERS_PARALLELISM"] = "false"

# Suppress noisy output from HuggingFace/ML libraries during model loading.
#
# Issues suppressed:
# 1. httpx.ReadTimeout from Thread-auto_conversion: The transformers library spawns
#    a background thread that queries HuggingFace Hub for safetensors conversion PRs.
#    This times out on slow networks, causing spurious error messages.
#
# 2. "Loading weights" progress bars: tqdm progress bars from mlx/safetensors during
#    model weight loading create visual noise in the CLI.
#
# 3. "UNEXPECTED" key warnings: Model architecture differences between training and
#    inference cause harmless warnings that confuse users.
#
# These are all cosmetic - they don't affect functionality. The settings below
# disable background checks and progress output while allowing model downloads.
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1")
os.environ.setdefault("TQDM_DISABLE", "1")  # Suppress progress bars during model loading

import asyncio
import platform
import sys
import webbrowser
from pathlib import Path

import click
from rich.console import Console

# Show loading indicator while importing heavy dependencies
_loading_console = Console()
with _loading_console.status("[bold cyan]🌳 Initializing ThreatForest...", spinner="dots"):
    from threatforest.config import ROOT_DIR, config
    from threatforest.agents.tracing_session import setup_langfuse_otel
    setup_langfuse_otel()
    from threatforest.modules.cli import CLIDisplay, CLIWizard, WorkflowRunner
    from threatforest.modules.utils.logger import ThreatForestLogger


console = Console()


def _resolve_workspace_root() -> Path:
    """Resolve the repo root directory."""
    package_dir = Path(__file__).resolve().parent
    return package_dir.parent.parent


def launch_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Start the FastAPI web console server and open the browser."""
    import threading
    import time

    repo_root = _resolve_workspace_root()
    src_dir = str(repo_root / "src")
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)

    console.print(f"[bold cyan]🌳 Starting ThreatForest Web Console on http://{host}:{port}[/bold cyan]")

    def open_browser():
        time.sleep(1.5)
        webbrowser.open(f"http://{host}:{port}")

    threading.Thread(target=open_browser, daemon=True).start()

    try:
        import uvicorn
        uvicorn.run("server.app:app", host=host, port=port, log_level="info")
    except KeyboardInterrupt:
        console.print("\n[cyan]👋 ThreatForest Web Console stopped.[/cyan]")
    except ImportError:
        console.print("[red]Error:[/red] uvicorn is not installed. Install it with: pip install uvicorn[standard]")
        sys.exit(1)
    except OSError as e:
        if "address already in use" in str(e).lower():
            console.print(f"[red]Error:[/red] Port {port} is already in use.")
            console.print(f"[dim]Try: threatforest --port {port + 1}[/dim]")
            sys.exit(1)
        raise


@click.group(invoke_without_command=True)
@click.option("--tui", is_flag=True, default=False, help="Run in interactive terminal mode")
@click.option("--host", default="127.0.0.1", help="Host for web console server")
@click.option("--port", default=8000, type=int, help="Port for web console server")
@click.pass_context
def cli(ctx, tui, host, port):
    """ThreatForest - AI-Driven Threat Modeling"""
    if ctx.invoked_subcommand is not None:
        return
    if tui:
        ctx.invoke(run)
    else:
        launch_server(host=host, port=port)


@cli.command()
@click.option("--project-path", "-p", default=None, help="Project directory path")
@click.option("--threat-model", "-t", default=None, help="Threat model file path (optional)")
@click.option(
    "--mode",
    "-m",
    type=click.Choice(["full", "enrich", "mitigate"]),
    default="full",
    help="Workflow mode",
)
@click.option("--input-dir", "-i", default=None, help="Input directory (for enrich/mitigate modes)")
@click.option(
    "--output-dir", "-o", default=None, help="Output directory (for enrich/mitigate modes)"
)
def run(project_path, threat_model, mode, input_dir, output_dir):
    """Run ThreatForest workflow"""

    display = CLIDisplay()
    wizard = CLIWizard()
    runner = WorkflowRunner()

    # Initialize logger using ROOT_DIR from config
    output_path = ROOT_DIR / "output"
    ThreatForestLogger.initialize(output_path)

    try:
        # Check and initialize config if needed (before anything else)
        wizard.check_and_init_config()

        # Show welcome
        display.show_welcome()

        # Show config from config.yaml (no secrets like AWS profile)
        # Detect active provider
        active_provider = None
        model_id = None
        
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
        else:
            active_provider = "Not configured"
            model_id = "None"
        
        config_display = {
            "model_provider": active_provider,
            "model_id": model_id,
            "embeddings_model": config.embeddings_model,
            "ttc_threshold": config.ttc_threshold,
        }

        display.show_config(config_display)

        # Interactive mode if no project path provided
        if project_path is None:
            # Loop to allow returning to menu after configuration changes
            while True:
                # Use wizard
                selected_mode = wizard.select_mode()

                # Handle exit
                if selected_mode == "exit":
                    console.print("\n[cyan]👋 Thanks for using ThreatForest![/cyan]\n")
                    sys.exit(0)

                # Handle configuration modes - don't exit, loop back to menu
                if selected_mode == "credentials":
                    wizard.update_credentials()
                    
                    # Reload environment variables
                    from dotenv import load_dotenv
                    from threatforest.config import ENV_FILE
                    load_dotenv(dotenv_path=ENV_FILE, override=True)
                    
                    # Show updated config
                    active_provider = None
                    model_id = None
                    
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
                    elif config.sagemaker and config.sagemaker.get("endpoint_name"):
                        active_provider = "AWS SageMaker"
                        model_id = config.sagemaker.get("endpoint_name")
                    
                    config_display = {
                        "model_provider": active_provider,
                        "model_id": model_id,
                        "embeddings_model": config.embeddings_model,
                        "ttc_threshold": config.ttc_threshold,
                    }
                    display.show_config(config_display)
                    
                    # Loop back to mode selection
                    continue
                
                elif selected_mode == "model_settings":
                    wizard.configure_model_settings()
                    
                    # Reload config
                    from threatforest.config import config as cfg
                    cfg._load_config()
                    
                    # Show updated config
                    active_provider = None
                    model_id = None
                    
                    if cfg.bedrock and cfg.bedrock.get("model_id"):
                        active_provider = "AWS Bedrock"
                        model_id = cfg.bedrock.get("model_id")
                    elif cfg.anthropic and cfg.anthropic.get("model_id"):
                        active_provider = "Anthropic"
                        model_id = cfg.anthropic.get("model_id")
                    elif cfg.openai and cfg.openai.get("model_id"):
                        active_provider = "OpenAI"
                        model_id = cfg.openai.get("model_id")
                    elif cfg.gemini and cfg.gemini.get("model_id"):
                        active_provider = "Google Gemini"
                        model_id = cfg.gemini.get("model_id")
                    elif cfg.ollama and cfg.ollama.get("model_id"):
                        active_provider = "Ollama"
                        model_id = cfg.ollama.get("model_id")
                    elif cfg.sagemaker and cfg.sagemaker.get("endpoint_name"):
                        active_provider = "AWS SageMaker"
                        model_id = cfg.sagemaker.get("endpoint_name")
                    
                    config_display = {
                        "model_provider": active_provider,
                        "model_id": model_id,
                        "embeddings_model": cfg.embeddings_model,
                        "ttc_threshold": cfg.ttc_threshold,
                    }
                    display.show_config(config_display)
                    
                    # Loop back to mode selection
                    continue

                wizard.show_mode_info(selected_mode)
                
                # Break out of loop to continue with workflow
                break

            # Only "full" mode in interactive - always run complete analysis
            # Get project path
            project_path = wizard.get_project_path()
            
            # Ask about threat statements (new agent-based workflow)
            has_threats, threat_file_path = wizard.ask_threat_statement_preference()

            # Show review configuration
            display.show_review_config(
                mode="full", 
                project_path=project_path, 
                threat_model=threat_file_path  # Use threat_file_path for display
            )

            # Confirm before starting
            if not wizard.confirm_continue("Ready to start analysis?"):
                display.show_info("Analysis cancelled by user")
                sys.exit(0)

            # Run full workflow with step indicator
            display.show_step_header(
                4, 4, "Executing Analysis", "This may take several minutes..."
            )
            result = runner.run_full_workflow(project_path, threat_file_path)

        else:
            # Non-interactive mode - project path provided
            if mode == "full":
                display.show_info(f"Running full workflow for: {project_path}")
                result = runner.run_full_workflow(project_path, threat_model)
            elif mode == "enrich":
                if input_dir is None or output_dir is None:
                    display.show_error(
                        "Enrich mode requires --input-dir and --output-dir",
                        suggestions=[
                            "Use --input-dir to specify input directory",
                            "Use --output-dir to specify output directory",
                            "Example: --input-dir ./output/attack_trees --output-dir ./output/enriched",
                        ],
                    )
                    sys.exit(1)
                display.show_info(f"Running enrichment: {input_dir} → {output_dir}")
                result = asyncio.run(runner.run_enrichment(input_dir, output_dir))
            elif mode == "mitigate":
                if input_dir is None or output_dir is None:
                    display.show_error(
                        "Mitigate mode requires --input-dir and --output-dir",
                        suggestions=[
                            "Use --input-dir to specify input directory",
                            "Use --output-dir to specify output directory",
                            "Example: --input-dir ./output/enriched --output-dir ./output/mitigated",
                        ],
                    )
                    sys.exit(1)
                display.show_info(f"Running mitigation mapping: {input_dir} → {output_dir}")
                result = asyncio.run(runner.run_mitigation(input_dir, output_dir))

        # Display results - check for both 'success' (enrich/mitigate) and 'status' (orchestrator)
        is_successful = result.get("success") or result.get("status") == "success"

        if is_successful:
            # Console success box removed for cleaner display
            
            # Build summary
            summary = {}
            if "enriched_count" in result:
                summary["attack_trees"] = result["enriched_count"]
            if "processed_count" in result:
                summary["attack_trees"] = result["processed_count"]
            if "techniques_with_mitigations" in result:
                summary["ttc_mappings"] = result["techniques_with_mitigations"]
            if "total_mitigations" in result:
                summary["total_mitigations"] = result["total_mitigations"]
            if "output_dir" in result:
                summary["output_dir"] = result["output_dir"]
            if "output_directory" in result:
                summary["output_dir"] = result["output_directory"]

            # Extract from orchestrator result if available
            if "context" in result:
                data = result.get("context", {})
                if "attack_trees" in data:
                    tree_data = data["attack_trees"]
                    if "generation_summary" in tree_data:
                        summary["attack_trees"] = tree_data["generation_summary"].get(
                            "successful_generations", 0
                        )
                if "extracted_info" in data:
                    extract_data = data["extracted_info"]
                    if "extraction_summary" in extract_data:
                        summary["threats_processed"] = extract_data["extraction_summary"].get(
                            "high_severity_count", 0
                        )

            display.show_summary(summary)

            # Get output directory for docs generation
            output_directory = (
                summary.get("output_dir")
                or result.get("output_dir")
                or result.get("output_directory")
            )

            # Get logger
            logger = ThreatForestLogger.get_logger()

            if output_directory:
                logger.info(f"Output directory: {output_directory}")
                console.print(f"\n📁 [bold cyan]Output Directory:[/bold cyan] {output_directory}\n")
                
                # Show and open HTML dashboard
                dashboard_path = Path(output_directory) / "attack_trees_dashboard.html"
                if dashboard_path.exists():
                    console.print(f"📊 [bold green]Interactive Dashboard:[/bold green] {dashboard_path}")
                    
                    # Auto-open in browser
                    try:
                        console.print(f"   [dim]Opening in browser...[/dim]")
                        dashboard_uri = dashboard_path.resolve().as_uri()
                        webbrowser.open(dashboard_uri)
                        console.print(f"   [green]✓ Dashboard opened in browser[/green]\n")
                    except Exception as e:
                        logger.warning(f"Failed to auto-open browser: {e}")
                        console.print(f"   [yellow]Could not auto-open browser[/yellow]")
                        console.print(f"   [dim]Open manually: {dashboard_path}[/dim]\n")
            else:
                logger.warning("No output directory found in result")
                console.print("\n[yellow]⚠️  Output directory information not available[/yellow]\n")
        else:
            error_msg = result.get("error", "Unknown error")
            suggestions = [
                "Check the logs for detailed error information",
                "Verify all configuration settings in config.yaml",
                "Ensure AWS credentials are properly configured",
            ]
            display.show_error(error_msg, "Workflow Failed", suggestions)
            sys.exit(1)

    except KeyboardInterrupt:
        console.print("\n\n[yellow]👋 ThreatForest interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        suggestions = [
            "Check logs in ./output directory",
            "Verify project structure and permissions",
            "Run with --help for usage information",
        ]
        display.show_error(str(e), "Unexpected Error", suggestions)
        import traceback

        console.print("\n[dim]Stack trace:[/dim]")
        console.print("[dim]" + traceback.format_exc() + "[/dim]")
        sys.exit(1)


@cli.command()
def status():
    """Show current workflow status"""
    display = CLIDisplay()
    display.print("Status command not yet implemented", style="yellow")



@cli.group()
def config_cmd():
    """Manage ThreatForest configuration"""
    pass


@config_cmd.command(name="init")
@click.option("--force", "-f", is_flag=True, help="Overwrite existing config")
def config_init(force):
    """Initialize user configuration file"""
    from threatforest.modules.utils.config_manager import ConfigManager

    manager = ConfigManager()
    manager.init_user_config(force=force)


@config_cmd.command(name="show")
def config_show():
    """Show current configuration"""
    from threatforest.modules.utils.config_manager import ConfigManager

    manager = ConfigManager()
    manager.show_config()


@config_cmd.command(name="edit")
def config_edit():
    """Edit configuration interactively"""
    from threatforest.modules.utils.config_manager import ConfigManager

    manager = ConfigManager()
    manager.edit_interactive()


@config_cmd.command(name="set")
@click.argument("key")
@click.argument("value")
def config_set(key, value):
    """Set a configuration value (e.g., threatforest config set bedrock.model_id claude-sonnet-4)"""
    from threatforest.modules.utils.config_manager import ConfigManager

    manager = ConfigManager()
    manager.set_value(key, value)


@config_cmd.command(name="path")
def config_path():
    """Show path to active config file"""
    from threatforest.modules.utils.config_manager import ConfigManager

    manager = ConfigManager()
    console.print(f"\n[cyan]Config file:[/cyan] {manager.get_config_path()}\n")


@config_cmd.command(name="langfuse")
@click.option("--enable/--disable", default=None, help="Enable or disable Langfuse tracing")
@click.option("--public-key", "-p", default=None, help="Langfuse public key (pk-lf-...)")
@click.option("--secret-key", "-s", default=None, help="Langfuse secret key (sk-lf-...)")
@click.option("--host", "-h", default=None, help="Langfuse host (default: https://cloud.langfuse.com)")
@click.option("--test", is_flag=True, help="Test the connection after configuring")
@click.option("--register-scores", is_flag=True, help="Register score definitions with Langfuse")
@click.option("--sync-scores", is_flag=True, help="Sync local registry with existing Langfuse score configs")
def config_langfuse(enable, public_key, secret_key, host, test, register_scores, sync_scores):
    """Configure Langfuse tracing credentials.
    
    Langfuse provides observability for your threat modeling workflows,
    enabling you to track traces, review outputs, and export data.
    
    Examples:
    
        # Interactive setup
        threatforest config langfuse
        
        # Set credentials directly
        threatforest config langfuse --public-key pk-lf-xxx --secret-key sk-lf-xxx
        
        # Enable with all options
        threatforest config langfuse --enable --public-key pk-lf-xxx --secret-key sk-lf-xxx --host https://cloud.langfuse.com
        
        # Disable Langfuse
        threatforest config langfuse --disable
        
        # Test existing configuration
        threatforest config langfuse --test
        
        # Register score definitions with Langfuse
        threatforest config langfuse --register-scores
        
        # Sync local registry with existing Langfuse configs
        threatforest config langfuse --sync-scores
    """
    from threatforest.modules.utils.env_manager import EnvManager
    from rich.panel import Panel
    
    env_manager = EnvManager()
    env_manager.ensure_exists()
    
    # If no options provided, run interactive setup
    if enable is None and public_key is None and secret_key is None and host is None and not test:
        console.print("\n[bold cyan]Langfuse Tracing Configuration[/bold cyan]")
        console.print("[dim]Langfuse provides observability for your threat modeling workflows.[/dim]")
        console.print("[dim]Get your API keys from: https://cloud.langfuse.com[/dim]\n")
        
        import questionary
        
        # Show current status
        current_enabled = env_manager.get_value('LANGFUSE_ENABLED') == 'true'
        current_public = env_manager.get_value('LANGFUSE_PUBLIC_KEY') or ''
        current_host = env_manager.get_value('LANGFUSE_HOST') or 'https://cloud.langfuse.com'
        
        if current_enabled and current_public:
            console.print(f"[green]✓[/green] Currently enabled with key: {current_public[:20]}...")
        else:
            console.print("[dim]○ Currently not configured[/dim]")
        console.print()
        
        # Ask if user wants to enable
        enable_choice = questionary.confirm(
            "Enable Langfuse tracing?",
            default=True
        ).ask()
        
        if not enable_choice:
            env_manager.set_value('LANGFUSE_ENABLED', 'false')
            console.print("\n[dim]Langfuse tracing disabled[/dim]\n")
            return
        
        # Get credentials
        public_key = questionary.text(
            "Langfuse Public Key (pk-lf-...):",
            default=current_public if current_public and 'your-public-key' not in current_public else ''
        ).ask()
        
        secret_key = questionary.password(
            "Langfuse Secret Key (sk-lf-...):"
        ).ask()
        
        host = questionary.text(
            "Langfuse Host (optional):",
            default=current_host
        ).ask()
        
        # Save
        env_manager.set_value('LANGFUSE_ENABLED', 'true')
        env_manager.set_value('LANGFUSE_PUBLIC_KEY', public_key)
        env_manager.set_value('LANGFUSE_SECRET_KEY', secret_key)
        if host:
            env_manager.set_value('LANGFUSE_HOST', host)
        
        console.print(f"\n[green]✓[/green] Langfuse configured successfully!")
        test = True  # Auto-test after interactive setup
    
    # Handle --disable flag
    elif enable is False:
        env_manager.set_value('LANGFUSE_ENABLED', 'false')
        console.print("\n[green]✓[/green] Langfuse tracing disabled\n")
        return
    
    # Handle direct credential setting
    else:
        if enable is True:
            env_manager.set_value('LANGFUSE_ENABLED', 'true')
        
        if public_key:
            env_manager.set_value('LANGFUSE_PUBLIC_KEY', public_key)
            console.print(f"[green]✓[/green] Public key configured")
        
        if secret_key:
            env_manager.set_value('LANGFUSE_SECRET_KEY', secret_key)
            console.print(f"[green]✓[/green] Secret key configured")
        
        if host:
            env_manager.set_value('LANGFUSE_HOST', host)
            console.print(f"[green]✓[/green] Host configured: {host}")
        
        if enable is True:
            console.print(f"[green]✓[/green] Langfuse tracing enabled")
    
    # Test connection if requested
    if test:
        console.print("\n[cyan]Testing Langfuse connection...[/cyan]")
        
        # Get current values
        test_public = public_key or env_manager.get_value('LANGFUSE_PUBLIC_KEY')
        test_secret = secret_key or env_manager.get_value('LANGFUSE_SECRET_KEY')
        test_host = host or env_manager.get_value('LANGFUSE_HOST') or 'https://cloud.langfuse.com'
        
        if not test_public or not test_secret:
            console.print("[red]Error:[/red] Missing public key or secret key")
            console.print("[dim]Configure credentials first: threatforest config langfuse[/dim]\n")
            return
        
        try:
            from langfuse import Langfuse
            client = Langfuse(
                public_key=test_public,
                secret_key=test_secret,
                host=test_host
            )
            client.auth_check()
            console.print(Panel(
                f"[green]✓ Connection successful![/green]\n\n"
                f"Host: {test_host}\n"
                f"Public Key: {test_public[:20]}...",
                title="Langfuse Connected",
                border_style="green"
            ))
            
            # Auto-register score configs on successful connection
            try:
                from threatforest.tracing.config import LangfuseConfig
                from threatforest.tracing.score_configs import ScoreConfigRegistry
                lf_config = LangfuseConfig(
                    enabled=True,
                    public_key=test_public,
                    secret_key=test_secret,
                    host=test_host,
                )
                registry = ScoreConfigRegistry(lf_config)
                registered = registry.register_all_score_definitions()
                console.print(f"[green]✓[/green] Registered {len(registered)} score config(s) with Langfuse")
            except Exception as e:
                console.print(f"[yellow]⚠️  Score config registration failed: {e}[/yellow]")
        except ImportError:
            console.print("[red]Error:[/red] Langfuse package not installed")
            console.print("[dim]Install with: pip install langfuse[/dim]\n")
        except Exception as e:
            console.print(f"[red]Connection failed:[/red] {e}")
            console.print("[dim]Please verify your credentials are correct[/dim]\n")
    
    # Handle score registration
    if register_scores or sync_scores:
        console.print("\n[cyan]Managing score configurations...[/cyan]")
        
        # Get current values
        reg_public = public_key or env_manager.get_value('LANGFUSE_PUBLIC_KEY')
        reg_secret = secret_key or env_manager.get_value('LANGFUSE_SECRET_KEY')
        reg_host = host or env_manager.get_value('LANGFUSE_HOST') or 'https://cloud.langfuse.com'
        
        if not reg_public or not reg_secret:
            console.print("[red]Error:[/red] Missing public key or secret key")
            console.print("[dim]Configure credentials first: threatforest config langfuse[/dim]\n")
            return
        
        try:
            from threatforest.tracing.config import LangfuseConfig
            from threatforest.tracing.score_configs import ScoreConfigRegistry
            
            langfuse_config = LangfuseConfig(
                enabled=True,
                public_key=reg_public,
                secret_key=reg_secret,
                host=reg_host
            )
            
            registry = ScoreConfigRegistry(langfuse_config)
            
            if sync_scores:
                console.print("[cyan]Syncing with existing Langfuse score configs...[/cyan]")
                registry.sync_with_langfuse()
                configs = registry.get_registered_configs()
                console.print(f"[green]✓[/green] Synced {len(configs)} score config(s) from Langfuse")
            
            if register_scores:
                console.print("[cyan]Registering ThreatForest score definitions...[/cyan]")
                registered = registry.register_all_score_definitions()
                
                if registered:
                    console.print(Panel(
                        f"[green]✓ Registered {len(registered)} score config(s) with Langfuse[/green]\n\n"
                        "Score configs enable server-side validation of scores.\n"
                        "View them in Langfuse: Settings → Score Configs",
                        title="Score Configs Registered",
                        border_style="green"
                    ))
                    
                    # Show registered scores
                    from rich.table import Table
                    score_table = Table(title="Registered Score Configs", show_header=True, header_style="bold cyan")
                    score_table.add_column("Name", style="cyan")
                    score_table.add_column("Type", style="white")
                    score_table.add_column("Config ID", style="dim")
                    
                    for name, config in sorted(registered.items()):
                        score_table.add_row(name, config.data_type, config.config_id[:20] + "...")
                    
                    console.print(score_table)
                else:
                    console.print("[yellow]No new score configs registered (may already exist)[/yellow]")
        
        except ImportError as e:
            console.print(f"[red]Error:[/red] {e}")
            console.print("[dim]Install required packages with: pip install langfuse[/dim]\n")
        except Exception as e:
            console.print(f"[red]Error registering score configs:[/red] {e}")
    
    console.print()


@cli.group()
def export():
    """Export traces from Langfuse to Langfuse Datasets for evaluation"""
    pass


@export.command(name="traces")
@click.option(
    "--trace-type",
    "-t",
    type=click.Choice(["threat_statement", "attack_tree", "ttp_matching"]),
    default=None,
    help="Filter by trace type",
)
@click.option(
    "--status",
    "-s",
    type=click.Choice(["pending_review", "reviewed"]),
    default=None,
    help="Filter by review status",
)
@click.option(
    "--start-date",
    type=str,
    default=None,
    help="Filter by start date (ISO format, e.g., 2024-01-01)",
)
@click.option(
    "--end-date",
    type=str,
    default=None,
    help="Filter by end date (ISO format, e.g., 2024-01-07)",
)
@click.option(
    "--ground-truth-only",
    is_flag=True,
    default=False,
    help="Only export ground truth candidates",
)
@click.option(
    "--dataset-name",
    "-d",
    required=True,
    help="Name of the Langfuse Dataset to export to",
)
@click.option(
    "--dataset-description",
    default=None,
    help="Description for the dataset (used when creating new dataset)",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show what would be exported without actually exporting",
)
def export_traces(trace_type, status, start_date, end_date, ground_truth_only, dataset_name, dataset_description, dry_run):
    """Export traces from Langfuse to a Langfuse Dataset.
    
    This command queries Langfuse for traces matching the specified filters
    and exports them to a Langfuse Dataset for evaluation. Dataset items include
    input/expected_output pairs that can be used for running experiments.
    
    Examples:
    
        # Export all reviewed attack tree traces to a dataset
        threatforest export traces --trace-type attack_tree --status reviewed -d attack-trees-v1
        
        # Export traces from a specific date range
        threatforest export traces --start-date 2024-01-01 --end-date 2024-01-07 -d weekly-eval
        
        # Export only ground truth candidates
        threatforest export traces --ground-truth-only -d ground-truth-v1
        
        # Dry run to see what would be exported
        threatforest export traces --trace-type attack_tree --dry-run -d test-dataset
    """
    from datetime import datetime as dt
    from rich.table import Table
    from rich.panel import Panel
    
    try:
        # Import tracing modules
        from threatforest.tracing.config import LangfuseConfig
        from threatforest.tracing.export import LangfuseDatasetExporter, ExportFilter
        
        # Parse dates if provided
        parsed_start_date = None
        parsed_end_date = None
        
        if start_date:
            try:
                parsed_start_date = dt.fromisoformat(start_date)
            except ValueError:
                console.print(f"[red]Error:[/red] Invalid start date format: {start_date}")
                console.print("[dim]Use ISO format, e.g., 2024-01-01 or 2024-01-01T00:00:00[/dim]")
                sys.exit(1)
        
        if end_date:
            try:
                parsed_end_date = dt.fromisoformat(end_date)
            except ValueError:
                console.print(f"[red]Error:[/red] Invalid end date format: {end_date}")
                console.print("[dim]Use ISO format, e.g., 2024-01-07 or 2024-01-07T23:59:59[/dim]")
                sys.exit(1)
        
        # Create export filter
        export_filter = ExportFilter(
            trace_type=trace_type,
            review_status=status,
            start_date=parsed_start_date,
            end_date=parsed_end_date,
            ground_truth_only=ground_truth_only,
        )
        
        # Validate filter
        try:
            export_filter.validate()
        except ValueError as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)
        
        # Display filter configuration
        console.print()
        filter_table = Table(title="Export Configuration", show_header=True, header_style="bold cyan")
        filter_table.add_column("Setting", style="cyan")
        filter_table.add_column("Value", style="white")
        
        filter_table.add_row("Dataset Name", dataset_name)
        filter_table.add_row("Trace Type", trace_type or "All")
        filter_table.add_row("Review Status", status or "All")
        filter_table.add_row("Start Date", start_date or "Not set")
        filter_table.add_row("End Date", end_date or "Not set")
        filter_table.add_row("Ground Truth Only", "Yes" if ground_truth_only else "No")
        
        console.print(filter_table)
        console.print()
        
        if dry_run:
            console.print(Panel(
                "[yellow]DRY RUN MODE[/yellow]\n\n"
                "This is a dry run. No traces will be exported.\n"
                "Remove --dry-run flag to perform actual export.",
                title="Dry Run",
                border_style="yellow"
            ))
            console.print()
            return
        
        # Load Langfuse configuration
        langfuse_config = LangfuseConfig.from_env()
        
        if not langfuse_config.enabled:
            console.print(Panel(
                "[yellow]Langfuse is not enabled.[/yellow]\n\n"
                "To enable Langfuse, set the following environment variables:\n"
                "  • LANGFUSE_ENABLED=true\n"
                "  • LANGFUSE_PUBLIC_KEY=<your-public-key>\n"
                "  • LANGFUSE_SECRET_KEY=<your-secret-key>\n"
                "  • LANGFUSE_HOST=<your-host> (optional)",
                title="Configuration Required",
                border_style="yellow"
            ))
            sys.exit(1)
        
        # Create exporter and run export
        console.print("[cyan]Connecting to Langfuse...[/cyan]")
        
        try:
            exporter = LangfuseDatasetExporter(langfuse_config=langfuse_config)
        except ValueError as e:
            console.print(f"[red]Configuration Error:[/red] {e}")
            sys.exit(1)
        except ImportError as e:
            console.print(f"[red]Missing Dependency:[/red] {e}")
            console.print("[dim]Install required packages with: pip install langfuse[/dim]")
            sys.exit(1)
        
        console.print("[cyan]Querying traces from Langfuse...[/cyan]")
        
        with console.status("[bold cyan]Exporting traces to dataset...", spinner="dots"):
            result = exporter.export_to_dataset(
                filters=export_filter,
                dataset_name=dataset_name,
                dataset_description=dataset_description,
            )
        
        # Display results
        console.print()
        result_table = Table(title="Export Results", show_header=True, header_style="bold green")
        result_table.add_column("Metric", style="cyan")
        result_table.add_column("Count", style="white", justify="right")
        
        result_table.add_row("Dataset Name", result.get("dataset_name", dataset_name))
        result_table.add_row("Total Traces Found", str(result.get("total_traces", 0)))
        result_table.add_row("Items Created", str(result.get("items_created", 0)))
        result_table.add_row("Items Skipped", str(result.get("items_skipped", 0)))
        
        console.print(result_table)
        console.print()
        
        items_created = result.get("items_created", 0)
        if items_created > 0:
            console.print(Panel(
                f"[green]✓ Successfully exported {items_created} item(s) to dataset '{dataset_name}'[/green]\n\n"
                f"View your dataset in Langfuse: Datasets → {dataset_name}",
                border_style="green"
            ))
        else:
            console.print(Panel(
                "[yellow]No traces found matching the specified filters.[/yellow]\n\n"
                "Try adjusting your filter criteria or check that traces exist in Langfuse.",
                title="No Results",
                border_style="yellow"
            ))
        
    except RuntimeError as e:
        console.print(f"[red]Export Error:[/red] {e}")
        console.print("[dim]Check your Langfuse connection and credentials.[/dim]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected Error:[/red] {e}")
        import traceback
        console.print("[dim]" + traceback.format_exc() + "[/dim]")
        sys.exit(1)


@cli.command()
def help_cmd():
    """Show help information"""
    console.print(
        """
[bold cyan]ThreatForest CLI Commands:[/bold cyan]

  [cyan]run[/cyan]              Run threat modeling workflow (interactive or with options)
  [cyan]config init[/cyan]      Initialize user configuration (~/.threatforest/config.yaml)
  [cyan]config show[/cyan]      Show current configuration
  [cyan]config edit[/cyan]      Edit configuration interactively
  [cyan]config set[/cyan]       Set a specific config value
  [cyan]config path[/cyan]      Show path to active config file
  [cyan]config langfuse[/cyan]  Configure Langfuse tracing credentials
  [cyan]export traces[/cyan]    Export traces from Langfuse to Langfuse Datasets
  [cyan]status[/cyan]           Show current workflow status

[bold]Examples:[/bold]

  # Interactive mode
  threatforest

  # Initialize user config
  threatforest config init

  # View configuration
  threatforest config show

  # Set specific value
  threatforest config set bedrock.model_id claude-sonnet-4

  # Configure Langfuse (interactive)
  threatforest config langfuse

  # Configure Langfuse (direct)
  threatforest config langfuse --public-key pk-lf-xxx --secret-key sk-lf-xxx --enable

  # Disable Langfuse
  threatforest config langfuse --disable

  # Test Langfuse connection
  threatforest config langfuse --test

  # Register score definitions with Langfuse
  threatforest config langfuse --register-scores

  # Sync local registry with existing Langfuse configs
  threatforest config langfuse --sync-scores

  # Full workflow with project path
  threatforest run --project-path /path/to/project

  # TTP enrichment only
  threatforest run --mode enrich --input-dir ./threatforest/attack_trees --output-dir ./threatforest/enriched

  # Export reviewed attack tree traces
  threatforest export traces --trace-type attack_tree --status reviewed -d my-dataset

  # Export traces from a date range
  threatforest export traces --start-date 2024-01-01 --end-date 2024-01-07 -d weekly-eval

  # Export only ground truth candidates
  threatforest export traces --ground-truth-only -d ground-truth-v1

  # View generated HTML dashboard
  open path/to/project/threatforest/attack_trees/attack_trees_dashboard.html

For more information, visit: https://github.com/aws-samples/sample-agentic-attack-tree-generator
    """
    )


def main():
    """Main entry point"""
    cli()


if __name__ == "__main__":
    main()
