#!/usr/bin/env python3
"""
ThreatForest Python CLI
Main command-line interface using Rich for display
"""
import os

# Suppress tokenizers parallelism warning
os.environ["TOKENIZERS_PARALLELISM"] = "false"

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
    from threatforest.modules.cli import CLIDisplay, CLIWizard, WorkflowRunner
    from threatforest.modules.utils.logger import ThreatForestLogger


console = Console()



@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """ThreatForest - AI-Driven Threat Modeling CLI"""
    if ctx.invoked_subcommand is None:
        # No subcommand - run interactive wizard
        ctx.invoke(run)


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

  # Full workflow with project path
  threatforest run --project-path /path/to/project

  # TTP enrichment only
  threatforest run --mode enrich --input-dir ./threatforest/attack_trees --output-dir ./threatforest/enriched

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
