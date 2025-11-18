#!/usr/bin/env python3
"""
ThreatForest Python CLI
Main command-line interface using Rich for display
"""
import sys
import asyncio
import click
from pathlib import Path
from rich.console import Console
from src.modules.cli import CLIWizard, CLIDisplay, WorkflowRunner
from src.config import config
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
    
    # Initialize logger
    output_path = Path(__file__).parent.parent.parent / 'output'
    ThreatForestLogger.initialize(output_path)
    
    try:
        # Show welcome
        display.show_welcome()
        
        # Show config from config.yaml
        display.show_config({
            'aws_profile': config.default_aws_profile,
            'bedrock_model': config.default_bedrock_model,
            'neptune_graph_id': config.neptune_graph_id,
            'neptune_region': config.neptune_region,
            'embeddings_mode': config.embeddings_mode
        })
        
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
                # Run full workflow
                display.print("\n[bold cyan]Starting Full Workflow...[/bold cyan]\n")
                result = runner.run_full_workflow(project_path, threat_model)
                
            elif selected_mode == 'enrich':
                # Get input/output directories
                input_dir, output_dir = wizard.get_input_output_dirs('enrich')
                # Run enrichment
                display.print("\n[bold cyan]Starting TTC Enrichment...[/bold cyan]\n")
                result = asyncio.run(runner.run_enrichment(input_dir, output_dir))
                
            elif selected_mode == 'mitigate':
                # Get input/output directories
                input_dir, output_dir = wizard.get_input_output_dirs('mitigate')
                # Run mitigation
                display.print("\n[bold cyan]Starting Mitigation Mapping...[/bold cyan]\n")
                result = asyncio.run(runner.run_mitigation(input_dir, output_dir))
        
        else:
            # Non-interactive mode - project path provided
            if mode == 'full':
                result = runner.run_full_workflow(project_path, threat_model)
            elif mode == 'enrich':
                if input_dir is None or output_dir is None:
                    display.show_error("Enrich mode requires --input-dir and --output-dir")
                    sys.exit(1)
                result = asyncio.run(runner.run_enrichment(input_dir, output_dir))
            elif mode == 'mitigate':
                if input_dir is None or output_dir is None:
                    display.show_error("Mitigate mode requires --input-dir and --output-dir")
                    sys.exit(1)
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
        else:
            error_msg = result.get('error', 'Unknown error')
            display.show_error(error_msg, "Workflow Failed")
            sys.exit(1)
    
    except KeyboardInterrupt:
        console.print("\n\n[yellow]👋 ThreatForest interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        display.show_error(str(e), "Unexpected Error")
        import traceback
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
