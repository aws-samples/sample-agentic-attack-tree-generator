#!/usr/bin/env python3
"""
ThreatForest Python CLI
Main command-line interface using Rich for display
"""
import sys
import asyncio
import subprocess
import click
from pathlib import Path
from rich.console import Console
from src.modules.cli import CLIWizard, CLIDisplay, WorkflowRunner
from src.config import config, ROOT_DIR
from src.modules.utils.logger import ThreatForestLogger


console = Console()


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """ThreatForest - AI-Driven Threat Modeling CLI"""
    if ctx.invoked_subcommand is None:
        # No subcommand - run interactive wizard
        ctx.invoke(run)


@cli.command()
@click.option('--project-path', '-p', default=None, help='Project directory path')
@click.option('--threat-model', '-t', default=None, help='Threat model file path (optional)')
@click.option('--mode', '-m', type=click.Choice(['full', 'enrich', 'mitigate']), default='full', help='Workflow mode')
@click.option('--input-dir', '-i', default=None, help='Input directory (for enrich/mitigate modes)')
@click.option('--output-dir', '-o', default=None, help='Output directory (for enrich/mitigate modes)')
def run(project_path, threat_model, mode, input_dir, output_dir):
    """Run ThreatForest workflow"""
    
    display = CLIDisplay()
    wizard = CLIWizard()
    runner = WorkflowRunner()
    
    # Initialize logger using ROOT_DIR from config
    output_path = ROOT_DIR / 'output'
    ThreatForestLogger.initialize(output_path)
    
    try:
        # Show welcome
        display.show_welcome()
        
        # Show config from config.yaml (conditionally show AWS profile)
        config_display = {
            'model': config.default_bedrock_model,
            'embeddings_model': config.embeddings_model,
            'graph_file': str(config.graph_file_path)
        }
        
        # Only show AWS profile if using AWS providers
        if (config.bedrock and config.bedrock.get('model_id')) or \
           (config.sagemaker and config.sagemaker.get('endpoint_name')):
            config_display['aws_profile'] = config.default_aws_profile
        
        display.show_config(config_display)
        
        # Interactive mode if no project path provided
        if project_path is None:
            # Use wizard
            selected_mode = wizard.select_mode()
            wizard.show_mode_info(selected_mode)
            
            if selected_mode == 'full':
                # Get project path
                project_path = wizard.get_project_path()
                # Get optional threat model
                threat_model = wizard.get_threat_model_path()
                
                # Show review configuration
                display.show_review_config(
                    mode='full',
                    project_path=project_path,
                    threat_model=threat_model
                )
                
                # Confirm before starting
                if not wizard.confirm_continue("Ready to start workflow?"):
                    display.show_info("Workflow cancelled by user")
                    sys.exit(0)
                
                # Run full workflow with step indicator
                display.show_step_header(4, 4, "Executing Workflow", "This may take several minutes...")
                result = runner.run_full_workflow(project_path, threat_model)
                
            elif selected_mode == 'enrich':
                # Get input/output directories
                input_dir, output_dir = wizard.get_input_output_dirs('enrich')
                
                # Show review configuration
                display.show_review_config(
                    mode='enrich',
                    input_dir=input_dir,
                    output_dir=output_dir
                )
                
                # Confirm before starting
                if not wizard.confirm_continue("Ready to start enrichment?"):
                    display.show_info("Enrichment cancelled by user")
                    sys.exit(0)
                
                # Run enrichment with step indicator
                display.show_step_header(3, 3, "Executing TTC Enrichment", "Mapping to MITRE ATT&CK...")
                result = asyncio.run(runner.run_enrichment(input_dir, output_dir))
                
            elif selected_mode == 'mitigate':
                # Get input/output directories
                input_dir, output_dir = wizard.get_input_output_dirs('mitigate')
                
                # Show review configuration
                display.show_review_config(
                    mode='mitigate',
                    input_dir=input_dir,
                    output_dir=output_dir
                )
                
                # Confirm before starting
                if not wizard.confirm_continue("Ready to start mitigation mapping?"):
                    display.show_info("Mitigation mapping cancelled by user")
                    sys.exit(0)
                
                # Run mitigation with step indicator
                display.show_step_header(3, 3, "Executing Mitigation Mapping", "Finding security controls...")
                result = asyncio.run(runner.run_mitigation(input_dir, output_dir))
        
        else:
            # Non-interactive mode - project path provided
            if mode == 'full':
                display.show_info(f"Running full workflow for: {project_path}")
                result = runner.run_full_workflow(project_path, threat_model)
            elif mode == 'enrich':
                if input_dir is None or output_dir is None:
                    display.show_error(
                        "Enrich mode requires --input-dir and --output-dir",
                        suggestions=[
                            "Use --input-dir to specify input directory",
                            "Use --output-dir to specify output directory",
                            "Example: --input-dir ./output/attack_trees --output-dir ./output/enriched"
                        ]
                    )
                    sys.exit(1)
                display.show_info(f"Running enrichment: {input_dir} → {output_dir}")
                result = asyncio.run(runner.run_enrichment(input_dir, output_dir))
            elif mode == 'mitigate':
                if input_dir is None or output_dir is None:
                    display.show_error(
                        "Mitigate mode requires --input-dir and --output-dir",
                        suggestions=[
                            "Use --input-dir to specify input directory",
                            "Use --output-dir to specify output directory",
                            "Example: --input-dir ./output/enriched --output-dir ./output/mitigated"
                        ]
                    )
                    sys.exit(1)
                display.show_info(f"Running mitigation mapping: {input_dir} → {output_dir}")
                result = asyncio.run(runner.run_mitigation(input_dir, output_dir))
        
        # Display results - check for both 'success' (enrich/mitigate) and 'status' (orchestrator)
        is_successful = result.get('success') or result.get('status') == 'success'
        
        if is_successful:
            display.show_success("Workflow completed successfully!")
            
            # Build summary
            summary = {}
            if 'enriched_count' in result:
                summary['attack_trees'] = result['enriched_count']
            if 'processed_count' in result:
                summary['attack_trees'] = result['processed_count']
            if 'techniques_with_mitigations' in result:
                summary['ttc_mappings'] = result['techniques_with_mitigations']
            if 'total_mitigations' in result:
                summary['total_mitigations'] = result['total_mitigations']
            if 'output_dir' in result:
                summary['output_dir'] = result['output_dir']
            if 'output_directory' in result:
                summary['output_dir'] = result['output_directory']
            
            # Extract from orchestrator result if available
            if 'context' in result:
                data = result.get('context', {})
                if 'attack_trees' in data:
                    tree_data = data['attack_trees']
                    if 'generation_summary' in tree_data:
                        summary['attack_trees'] = tree_data['generation_summary'].get('successful_generations', 0)
                if 'extracted_info' in data:
                    extract_data = data['extracted_info']
                    if 'extraction_summary' in extract_data:
                        summary['threats_processed'] = extract_data['extraction_summary'].get('high_severity_count', 0)
            
            display.show_summary(summary)
            
            # Auto-open dashboard if it exists
            output_directory = summary.get('output_dir') or result.get('output_dir') or result.get('output_directory')
            if output_directory:
                dashboard_path = Path(output_directory) / 'attack_trees' / 'attack_trees_dashboard.html'
                if dashboard_path.exists():
                    display.show_info("🌐 Opening dashboard in browser...")
                    try:
                        subprocess.run(['open', str(dashboard_path)], check=False)
                    except Exception as e:
                        display.show_info(f"Could not auto-open dashboard: {e}")
                        display.show_info(f"📊 Dashboard: {dashboard_path}")
        else:
            error_msg = result.get('error', 'Unknown error')
            suggestions = [
                "Check the logs for detailed error information",
                "Verify all configuration settings in config.yaml",
                "Ensure AWS credentials are properly configured"
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
            "Run with --help for usage information"
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


@cli.command()
def help_cmd():
    """Show help information"""
    console.print("""
[bold cyan]ThreatForest CLI Commands:[/bold cyan]

  [cyan]run[/cyan]           Run threat modeling workflow (interactive or with options)
  [cyan]status[/cyan]        Show current workflow status
  [cyan]help[/cyan]          Show this help message

[bold]Examples:[/bold]

  # Interactive mode
  python -m src.cli run

  # Full workflow with project path
  python -m src.cli run --project-path /path/to/project

  # TTC enrichment only
  python -m src.cli run --mode enrich --input-dir ./output/attack_trees --output-dir ./output/enriched

  # Mitigation mapping only
  python -m src.cli run --mode mitigate --input-dir ./output/enriched --output-dir ./output/mitigated

For more information, visit: https://github.com/threatforest
    """)


def main():
    """Main entry point"""
    cli()


if __name__ == '__main__':
    main()
