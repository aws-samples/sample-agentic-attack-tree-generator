"""
Command-line interface for ThreatForest.

This module provides the main CLI application using Click framework,
with commands for analyzing projects and managing configuration.
"""

import os
import sys
import time
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.live import Live
from rich.layout import Layout
from rich.align import Align

from .config import ConfigManager, ThreatForestConfig
from .models import AnalysisResult, ContextInformation
from .error_handler import ErrorHandler, setup_logging, get_logger


console = Console()


class ThreatForestCLI:
    """Main CLI application class."""
    
    def __init__(self):
        self.config_manager = ConfigManager()
        self.config: Optional[ThreatForestConfig] = None
        self.error_handler: Optional[ErrorHandler] = None
        self.logger = None
        self.interactive_mode = True
    
    def load_config(
        self,
        config_file: Optional[str] = None,
        cli_overrides: Optional[Dict[str, Any]] = None
    ) -> ThreatForestConfig:
        """Load configuration from all sources."""
        try:
            self.config = self.config_manager.load_config(
                cli_args=cli_overrides,
                config_file=config_file
            )
            
            # Set up logging based on configuration
            log_level = cli_overrides.get('log_level', 'INFO') if cli_overrides else 'INFO'
            log_file = cli_overrides.get('log_file') if cli_overrides else None
            
            self.logger = setup_logging(
                log_level=log_level,
                log_file=log_file,
                include_console=True
            )
            
            # Initialize error handler
            self.error_handler = ErrorHandler(self.logger)
            
            return self.config
        except Exception as e:
            if self.error_handler:
                self.error_handler.handle_error(e, operation="configuration loading")
            console.print(f"[red]Error loading configuration: {e}[/red]")
            sys.exit(1)
    
    def validate_aws_credentials(self) -> bool:
        """Validate AWS credentials are available."""
        # Check for AWS credentials in environment or AWS config
        aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
        aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
        aws_profile = os.getenv('AWS_PROFILE')
        
        if not (aws_access_key and aws_secret_key) and not aws_profile:
            console.print(Panel(
                "[red]AWS credentials not found![/red]\n\n"
                "Please set up AWS credentials using one of these methods:\n"
                "1. Environment variables:\n"
                "   export AWS_ACCESS_KEY_ID=your_key\n"
                "   export AWS_SECRET_ACCESS_KEY=your_secret\n"
                "   export AWS_DEFAULT_REGION=us-east-1\n\n"
                "2. AWS CLI profile:\n"
                "   aws configure\n\n"
                "3. AWS profile environment variable:\n"
                "   export AWS_PROFILE=your_profile",
                title="AWS Credentials Required",
                border_style="red"
            ))
            return False
        
        return True
    
    def validate_extracted_information(self, context_info: ContextInformation) -> ContextInformation:
        """
        Interactive validation of extracted context information.
        
        Args:
            context_info: Extracted context information to validate
            
        Returns:
            Validated and potentially modified context information
        """
        if not self.interactive_mode:
            return context_info
        
        console.print("\n" + "="*60)
        console.print("[bold blue]Information Extraction Results[/bold blue]")
        console.print("="*60)
        
        # Display extracted information in a table
        table = Table(title="Extracted Context Information", show_header=True, header_style="bold magenta")
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Values", style="white")
        
        table.add_row("Technologies", ", ".join(context_info.technologies) if context_info.technologies else "None detected")
        table.add_row("Programming Languages", ", ".join(context_info.programming_languages) if context_info.programming_languages else "None detected")
        table.add_row("Business Sector", context_info.sector or "Not specified")
        table.add_row("Security Objectives", ", ".join(context_info.security_objectives) if context_info.security_objectives else "None specified")
        table.add_row("Architecture Type", context_info.architecture_type or "Not specified")
        table.add_row("Compliance Frameworks", ", ".join(context_info.compliance_frameworks) if context_info.compliance_frameworks else "None detected")
        
        console.print(table)
        
        # Ask for validation
        console.print(f"\n[bold]Confidence Score:[/bold] {context_info.confidence_score:.1%}")
        
        if context_info.confidence_score < 0.7:
            console.print("[yellow]⚠️  Low confidence in extraction results. Please review carefully.[/yellow]")
        
        # Interactive validation
        while True:
            choice = Prompt.ask(
                "\nWhat would you like to do?",
                choices=["approve", "modify", "reject", "help"],
                default="approve"
            )
            
            if choice == "help":
                self._show_validation_help()
                continue
            elif choice == "approve":
                console.print("[green]✓ Information approved[/green]")
                context_info.validation_status = "approved"
                return context_info
            elif choice == "reject":
                console.print("[red]✗ Information rejected[/red]")
                context_info.validation_status = "rejected"
                return context_info
            elif choice == "modify":
                return self._modify_context_information(context_info)
    
    def _show_validation_help(self):
        """Show help for the validation process."""
        help_panel = Panel(
            "[bold]Validation Options:[/bold]\n\n"
            "[green]approve[/green] - Accept the extracted information as-is\n"
            "[yellow]modify[/yellow] - Edit specific fields before proceeding\n"
            "[red]reject[/red] - Reject the extraction and use minimal defaults\n"
            "[blue]help[/blue] - Show this help message\n\n"
            "[bold]Tips:[/bold]\n"
            "• Review the confidence score - low scores may indicate inaccurate extraction\n"
            "• Check that technologies and languages match your project\n"
            "• Ensure security objectives align with your threat model\n"
            "• Compliance frameworks should match your regulatory requirements",
            title="Validation Help",
            border_style="blue"
        )
        console.print(help_panel)
    
    def _modify_context_information(self, context_info: ContextInformation) -> ContextInformation:
        """Allow user to modify extracted context information."""
        console.print("\n[bold]Modify Context Information[/bold]")
        console.print("Press Enter to keep current value, or type new value:")
        
        # Modify technologies
        current_tech = ", ".join(context_info.technologies) if context_info.technologies else ""
        new_tech = Prompt.ask(f"Technologies [{current_tech}]", default=current_tech)
        if new_tech != current_tech:
            context_info.technologies = [t.strip() for t in new_tech.split(",") if t.strip()]
        
        # Modify programming languages
        current_langs = ", ".join(context_info.programming_languages) if context_info.programming_languages else ""
        new_langs = Prompt.ask(f"Programming Languages [{current_langs}]", default=current_langs)
        if new_langs != current_langs:
            context_info.programming_languages = [l.strip() for l in new_langs.split(",") if l.strip()]
        
        # Modify sector
        new_sector = Prompt.ask(f"Business Sector [{context_info.sector}]", default=context_info.sector or "")
        if new_sector:
            context_info.sector = new_sector
        
        # Modify security objectives
        current_objectives = ", ".join(context_info.security_objectives) if context_info.security_objectives else ""
        new_objectives = Prompt.ask(f"Security Objectives [{current_objectives}]", default=current_objectives)
        if new_objectives != current_objectives:
            context_info.security_objectives = [o.strip() for o in new_objectives.split(",") if o.strip()]
        
        # Modify architecture type
        new_arch = Prompt.ask(f"Architecture Type [{context_info.architecture_type}]", default=context_info.architecture_type or "")
        if new_arch:
            context_info.architecture_type = new_arch
        
        # Modify compliance frameworks
        current_compliance = ", ".join(context_info.compliance_frameworks) if context_info.compliance_frameworks else ""
        new_compliance = Prompt.ask(f"Compliance Frameworks [{current_compliance}]", default=current_compliance)
        if new_compliance != current_compliance:
            context_info.compliance_frameworks = [c.strip() for c in new_compliance.split(",") if c.strip()]
        
        console.print("[green]✓ Information updated[/green]")
        context_info.validation_status = "modified"
        return context_info
    
    def show_progress(self, phases: List[str]) -> Progress:
        """
        Create and return a progress tracker for workflow phases.
        
        Args:
            phases: List of phase names to track
            
        Returns:
            Rich Progress instance with task IDs
        """
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(complete_style="green", finished_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TimeElapsedColumn(),
            console=console,
            expand=True
        )
        
        # Add main workflow task
        workflow_task = progress.add_task(
            "[bold blue]🔍 ThreatForest Analysis", 
            total=len(phases)
        )
        
        # Add individual phase tasks
        phase_tasks = {}
        phase_icons = {
            "Context Detection": "📁",
            "Information Extraction": "🔍", 
            "Attack Tree Generation": "🌳",
            "TTC Enhancement": "🛡️",
            "Report Generation": "📄"
        }
        
        for phase in phases:
            icon = phase_icons.get(phase, "⚙️")
            task_id = progress.add_task(
                f"  {icon} {phase}", 
                total=100, 
                visible=False
            )
            phase_tasks[phase] = task_id
        
        return progress, workflow_task, phase_tasks
    
    def update_phase_progress(self, progress: Progress, phase_tasks: Dict[str, int], phase: str, percentage: int, description: str = ""):
        """Update progress for a specific phase with enhanced status indicators."""
        if phase in phase_tasks:
            task_id = phase_tasks[phase]
            
            # Add status indicators based on progress
            if percentage == 100:
                status_icon = "✅"
                status_style = "green"
            elif percentage >= 50:
                status_icon = "⚡"
                status_style = "yellow"
            else:
                status_icon = "⏳"
                status_style = "blue"
            
            phase_icons = {
                "Context Detection": "📁",
                "Information Extraction": "🔍", 
                "Attack Tree Generation": "🌳",
                "TTC Enhancement": "🛡️",
                "Report Generation": "📄"
            }
            
            icon = phase_icons.get(phase, "⚙️")
            
            if description:
                display_text = f"  {icon} {phase}: {description} {status_icon}"
            else:
                display_text = f"  {icon} {phase} {status_icon}"
            
            progress.update(
                task_id, 
                completed=percentage, 
                description=f"[{status_style}]{display_text}[/{status_style}]", 
                visible=True
            )
    
    def show_analysis_summary(self, results: Dict[str, Any]):
        """Display a comprehensive analysis summary."""
        console.print("\n" + "="*80)
        console.print("[bold green]ThreatForest Analysis Complete![/bold green]")
        console.print("="*80)
        
        # Create summary table
        summary_table = Table(title="Analysis Summary", show_header=True, header_style="bold cyan")
        summary_table.add_column("Metric", style="white", no_wrap=True)
        summary_table.add_column("Value", style="green")
        
        # Add summary data
        summary_table.add_row("Status", results.get('status', 'Unknown'))
        summary_table.add_row("Duration", f"{results.get('duration_seconds', 0):.1f} seconds")
        summary_table.add_row("Context Files Found", str(len(results.get('results', {}).get('context_files', []))))
        summary_table.add_row("Attack Trees Generated", str(len(results.get('results', {}).get('attack_trees', []))))
        summary_table.add_row("Errors Encountered", str(len(results.get('errors', []))))
        
        console.print(summary_table)
        
        # Show error summary if any
        if results.get('error_summary', {}).get('total_errors', 0) > 0:
            error_summary = results['error_summary']
            console.print(f"\n[yellow]⚠️  {error_summary['total_errors']} errors encountered during analysis[/yellow]")
            
            if error_summary.get('by_severity'):
                error_table = Table(title="Error Summary", show_header=True, header_style="bold red")
                error_table.add_column("Severity", style="white")
                error_table.add_column("Count", style="red")
                
                for severity, count in error_summary['by_severity'].items():
                    error_table.add_row(severity.title(), str(count))
                
                console.print(error_table)
        
        # Show output files
        if results.get('results', {}).get('summary_file'):
            console.print(f"\n[bold]📄 Summary Report:[/bold] {results['results']['summary_file']}")
        
        if results.get('results', {}).get('attack_trees'):
            console.print(f"\n[bold]🌳 Attack Trees Generated:[/bold]")
            for i, tree in enumerate(results['results']['attack_trees'], 1):
                if isinstance(tree, dict):
                    console.print(f"  {i}. {tree.get('title', 'Unknown')} (ID: {tree.get('threat_id', 'Unknown')})")
                else:
                    console.print(f"  {i}. {tree.title} (ID: {tree.threat_id})")
        
        console.print(f"\n[green]✅ Analysis complete! Check the output directory for generated files.[/green]")


# Create CLI instance
cli_app = ThreatForestCLI()


@click.group(invoke_without_command=True)
@click.option('--version', is_flag=True, help='Show version information')
@click.pass_context
def main(ctx, version):
    """
    ThreatForest - Agentic AI application for automated attack tree generation.
    
    Analyzes application context files and generates Mermaid-formatted attack trees
    enhanced with STIX threat intelligence.
    """
    if version:
        from . import __version__
        console.print(f"ThreatForest version {__version__}")
        return
    
    if ctx.invoked_subcommand is None:
        _show_welcome_screen()


@main.command()
@click.argument('directory', type=click.Path(exists=True, file_okay=False), default='.')
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
@click.option('--output', '-o', type=click.Path(), help='Output directory')
@click.option('--region', help='AWS Bedrock region')
@click.option('--model', help='Bedrock model to use')
@click.option('--severity', type=click.Choice(['low', 'medium', 'high']), help='Minimum severity threshold')
@click.option('--dry-run', is_flag=True, help='Show what would be analyzed without processing')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--non-interactive', is_flag=True, help='Run in non-interactive mode (skip user validation)')
@click.option('--auto-approve', is_flag=True, help='Automatically approve extracted information')
@click.option('--examples', is_flag=True, help='Show usage examples and exit')
def analyze(directory, config, output, region, model, severity, dry_run, verbose, non_interactive, auto_approve, examples):
    """
    Analyze a project directory for threats and generate attack trees.
    
    DIRECTORY: Path to the project directory to analyze (default: current directory)
    
    Examples:
    
      # Basic analysis of current directory
      tf analyze
      
      # Analyze specific directory with custom output
      tf analyze /path/to/project --output ./threat-analysis
      
      # Non-interactive mode for CI/CD
      tf analyze --non-interactive --auto-approve
      
      # Dry run to see what would be analyzed
      tf analyze --dry-run
      
      # Show detailed examples
      tf analyze --examples
    """
    
    if examples:
        _show_usage_examples()
        return
    # Set interactive mode
    cli_app.interactive_mode = not non_interactive
    
    console.print(f"[blue]🔍 Starting ThreatForest analysis of: {directory}[/blue]")
    
    # Build CLI overrides
    cli_overrides = {}
    if output:
        cli_overrides['output'] = {'directory': output}
    if region:
        cli_overrides['bedrock'] = {'region': region}
    if model:
        if 'bedrock' not in cli_overrides:
            cli_overrides['bedrock'] = {}
        cli_overrides['bedrock']['model'] = model
    if severity:
        cli_overrides['processing'] = {'severity_threshold': severity}
    
    # Load configuration
    config_obj = cli_app.load_config(config_file=config, cli_overrides=cli_overrides)
    
    if verbose:
        console.print(f"[dim]Configuration loaded from: {config or 'default sources'}[/dim]")
        console.print(f"[dim]Output directory: {config_obj.output.directory}[/dim]")
        console.print(f"[dim]Bedrock region: {config_obj.bedrock.region}[/dim]")
        console.print(f"[dim]Severity threshold: {config_obj.processing.severity_threshold}[/dim]")
        console.print(f"[dim]Interactive mode: {'Disabled' if non_interactive else 'Enabled'}[/dim]")
    
    # Validate AWS credentials
    if not cli_app.validate_aws_credentials():
        sys.exit(1)
    
    if dry_run:
        console.print("[yellow]📋 Dry run mode - showing what would be analyzed:[/yellow]")
        _show_dry_run_info(directory, config_obj)
        return
    
    # Run the analysis workflow
    try:
        results = _run_analysis_workflow(directory, config_obj, verbose, auto_approve)
        cli_app.show_analysis_summary(results)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Analysis interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        if cli_app.error_handler:
            error_context = cli_app.error_handler.handle_error(e, operation="analysis workflow")
            console.print(f"\n[red]❌ Analysis failed: {error_context.message}[/red]")
            if error_context.suggested_actions:
                console.print("\n[bold]Suggested actions:[/bold]")
                for action in error_context.suggested_actions:
                    console.print(f"  • {action}")
        else:
            console.print(f"\n[red]❌ Analysis failed: {e}[/red]")
        sys.exit(1)


@main.command()
def status():
    """Check ThreatForest system status and requirements."""
    console.print("[bold blue]🔍 ThreatForest System Status[/bold blue]\n")
    
    status_table = Table(title="System Requirements", show_header=True, header_style="bold cyan")
    status_table.add_column("Component", style="white", no_wrap=True)
    status_table.add_column("Status", style="white")
    status_table.add_column("Details", style="dim")
    
    # Check Python version
    import sys
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    python_ok = sys.version_info >= (3, 9)
    python_status = "[green]✅ OK[/green]" if python_ok else "[red]❌ FAIL[/red]"
    status_table.add_row("Python Version", python_status, f"v{python_version} (requires 3.9+)")
    
    # Check AWS credentials
    aws_ok = cli_app.validate_aws_credentials()
    aws_status = "[green]✅ OK[/green]" if aws_ok else "[red]❌ MISSING[/red]"
    aws_details = "Credentials found" if aws_ok else "Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or AWS_PROFILE"
    status_table.add_row("AWS Credentials", aws_status, aws_details)
    
    # Check configuration
    try:
        config_obj = cli_app.load_config()
        config_status = "[green]✅ OK[/green]"
        config_details = f"Region: {config_obj.bedrock.region}, Model: {config_obj.bedrock.model}"
    except Exception as e:
        config_status = "[red]❌ ERROR[/red]"
        config_details = str(e)
    
    status_table.add_row("Configuration", config_status, config_details)
    
    # Check dependencies
    try:
        import boto3
        import rich
        import click
        deps_status = "[green]✅ OK[/green]"
        deps_details = "All required packages installed"
    except ImportError as e:
        deps_status = "[red]❌ MISSING[/red]"
        deps_details = f"Missing package: {e.name}"
    
    status_table.add_row("Dependencies", deps_status, deps_details)
    
    console.print(status_table)
    
    # Overall status
    overall_ok = python_ok and aws_ok and config_status == "[green]✅ OK[/green]"
    if overall_ok:
        console.print("\n[bold green]🎉 ThreatForest is ready to use![/bold green]")
        console.print("Run 'tf analyze' to start analyzing your project.")
    else:
        console.print("\n[bold red]⚠️  Some issues need to be resolved before using ThreatForest.[/bold red]")
        console.print("Please address the issues marked above.")


@main.command()
@click.argument('project_path', type=click.Path(), default='.')
def init(project_path):
    """Initialize a new project directory with ThreatForest template files."""
    project_dir = Path(project_path)
    
    if not project_dir.exists():
        if Confirm.ask(f"Directory {project_path} doesn't exist. Create it?"):
            try:
                project_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                console.print(f"[red]Error creating directory: {e}[/red]")
                sys.exit(1)
        else:
            console.print("[yellow]Initialization cancelled.[/yellow]")
            return
    
    console.print(f"[blue]🚀 Initializing ThreatForest project in: {project_dir.absolute()}[/blue]\n")
    
    # Create template files
    templates = {
        'README.md': _get_readme_template(),
        'threats.md': _get_threats_template(),
        '.tf/config.yaml': _get_config_template()
    }
    
    created_files = []
    skipped_files = []
    
    for filename, content in templates.items():
        file_path = project_dir / filename
        
        if file_path.exists():
            if not Confirm.ask(f"File {filename} already exists. Overwrite?"):
                skipped_files.append(filename)
                continue
        
        # Create directory if needed
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write file
        file_path.write_text(content)
        created_files.append(filename)
    
    # Show results
    if created_files:
        console.print("[bold green]✅ Created files:[/bold green]")
        for filename in created_files:
            console.print(f"  • {filename}")
    
    if skipped_files:
        console.print(f"\n[yellow]⏭️  Skipped existing files:[/yellow]")
        for filename in skipped_files:
            console.print(f"  • {filename}")
    
    console.print(f"\n[bold blue]🎯 Next steps:[/bold blue]")
    console.print("1. Edit README.md with your project details")
    console.print("2. Add threat statements to threats.md")
    console.print("3. Run 'tf analyze' to generate attack trees")
    console.print("4. Review and customize .tf/config.yaml as needed")


@main.group()
def config():
    """Manage ThreatForest configuration."""
    pass


@config.command('show')
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
def config_show(config):
    """Show current configuration."""
    config_obj = cli_app.load_config(config_file=config)
    
    console.print(Panel(
        f"[bold]Bedrock Configuration:[/bold]\n"
        f"Region: {config_obj.bedrock.region}\n"
        f"Model: {config_obj.bedrock.model}\n"
        f"Timeout: {config_obj.bedrock.timeout_seconds}s\n\n"
        f"[bold]Processing Configuration:[/bold]\n"
        f"Severity Threshold: {config_obj.processing.severity_threshold}\n"
        f"Max Concurrent Agents: {config_obj.processing.max_concurrent_agents}\n"
        f"Timeout: {config_obj.processing.timeout_seconds}s\n\n"
        f"[bold]Output Configuration:[/bold]\n"
        f"Directory: {config_obj.output.directory}\n"
        f"Format: {config_obj.output.format}\n"
        f"Include Summary: {config_obj.output.include_summary}\n\n"
        f"[bold]TTC Configuration:[/bold]\n"
        f"AAF Bundle Path: {config_obj.ttc.aaf_bundle_path}\n"
        f"Alignment Threshold: {config_obj.ttc.alignment_threshold}\n"
        f"Enhancement Enabled: {config_obj.ttc.enable_enhancement}",
        title="ThreatForest Configuration",
        border_style="blue"
    ))


@config.command('set')
@click.argument('key')
@click.argument('value')
@click.option('--user', is_flag=True, help='Save to user-level configuration')
def config_set(key, value, user):
    """
    Set a configuration value.
    
    KEY: Configuration key (e.g., bedrock.region, processing.severity_threshold)
    VALUE: Configuration value
    """
    # Load current configuration
    config_obj = cli_app.load_config()
    
    # Parse the key path
    keys = key.split('.')
    if len(keys) != 2:
        console.print("[red]Error: Key must be in format 'section.field' (e.g., 'bedrock.region')[/red]")
        sys.exit(1)
    
    section, field = keys
    
    # Convert value to appropriate type
    converted_value = _convert_config_value(value)
    
    # Update configuration
    updates = {section: {field: converted_value}}
    
    try:
        updated_config = cli_app.config_manager.update_config(updates)
        cli_app.config_manager.save_config(updated_config, user_level=user)
        
        console.print(f"[green]Configuration updated: {key} = {converted_value}[/green]")
        if user:
            console.print("[dim]Saved to user-level configuration[/dim]")
        else:
            console.print("[dim]Saved to project-level configuration[/dim]")
            
    except Exception as e:
        console.print(f"[red]Error updating configuration: {e}[/red]")
        sys.exit(1)


def _show_dry_run_info(directory: str, config: ThreatForestConfig):
    """Show information about what would be analyzed in dry run mode."""
    dir_path = Path(directory)
    
    console.print(f"\n[bold]Directory to analyze:[/bold] {dir_path.absolute()}")
    console.print(f"[bold]Output directory:[/bold] {config.output.directory}")
    console.print(f"[bold]Bedrock region:[/bold] {config.bedrock.region}")
    console.print(f"[bold]Bedrock model:[/bold] {config.bedrock.model}")
    console.print(f"[bold]Severity threshold:[/bold] {config.processing.severity_threshold}")
    
    # Show files that would be scanned
    console.print(f"\n[bold]File patterns to scan:[/bold]")
    for pattern in config.files.context_patterns:
        console.print(f"  • {pattern}")
    
    # Find matching files
    matching_files = []
    for pattern in config.files.context_patterns:
        matching_files.extend(dir_path.glob(pattern))
    
    if matching_files:
        console.print(f"\n[bold]Files found ({len(matching_files)}):[/bold]")
        for file_path in sorted(set(matching_files)):
            console.print(f"  • {file_path.name}")
    else:
        console.print(f"\n[yellow]No matching context files found in {directory}[/yellow]")
        console.print("Consider adding README.md, architecture diagrams, or threat files.")


def _show_welcome_screen():
    """Display welcome screen with usage information."""
    welcome_panel = Panel(
        "[bold blue]Welcome to ThreatForest[/bold blue] [green]🌳[/green]\n\n" +
        "[bold]Agentic AI application for automated attack tree generation[/bold]\n\n" +
        "ThreatForest analyzes your application context and generates\n" +
        "Mermaid-formatted attack trees enhanced with STIX threat intelligence.\n\n" +
        "[bold cyan]Quick Start:[/bold cyan]\n" +
        "  tf analyze                    # Analyze current directory\n" +
        "  tf analyze /path/to/project   # Analyze specific directory\n" +
        "  tf analyze --help             # Show detailed help\n\n" +
        "[bold cyan]Configuration:[/bold cyan]\n" +
        "  tf config show                # Show current configuration\n" +
        "  tf config set bedrock.region us-east-1  # Set configuration\n\n" +
        "[bold cyan]Examples:[/bold cyan]\n" +
        "  tf analyze --dry-run          # Preview what would be analyzed\n" +
        "  tf analyze --verbose          # Show detailed progress\n" +
        "  tf analyze --non-interactive  # Run without user prompts\n\n" +
        "[dim]Use 'tf --help' for more information[/dim]",
        title="ThreatForest CLI",
        border_style="blue",
        padding=(1, 2)
    )
    
    console.print(welcome_panel)


def _show_usage_examples():
    """Display comprehensive usage examples."""
    examples_panel = Panel(
        "[bold blue]ThreatForest Usage Examples[/bold blue]\n\n" +
        
        "[bold yellow]Basic Usage:[/bold yellow]\n" +
        "  tf analyze                           # Analyze current directory\n" +
        "  tf analyze /path/to/project          # Analyze specific project\n" +
        "  tf analyze --dry-run                 # Preview analysis without execution\n\n" +
        
        "[bold yellow]Configuration Options:[/bold yellow]\n" +
        "  tf analyze --region us-west-2        # Use specific AWS region\n" +
        "  tf analyze --model claude-3-haiku    # Use specific Bedrock model\n" +
        "  tf analyze --severity high           # Only process high-severity threats\n" +
        "  tf analyze --output ./results        # Custom output directory\n\n" +
        
        "[bold yellow]Automation & CI/CD:[/bold yellow]\n" +
        "  tf analyze --non-interactive         # Skip user prompts\n" +
        "  tf analyze --auto-approve            # Auto-approve extracted info\n" +
        "  tf analyze --non-interactive --auto-approve --verbose  # Full automation\n\n" +
        
        "[bold yellow]Configuration Management:[/bold yellow]\n" +
        "  tf config show                       # Display current configuration\n" +
        "  tf config set bedrock.region us-east-1     # Set AWS region\n" +
        "  tf config set processing.severity_threshold medium  # Set severity\n" +
        "  tf config set ttc.enable_enhancement false # Disable TTC enhancement\n\n" +
        
        "[bold yellow]Project Setup Examples:[/bold yellow]\n" +
        "  # For a web application\n" +
        "  tf analyze --severity medium --model claude-3-sonnet\n\n" +
        "  # For a microservices architecture\n" +
        "  tf analyze --output ./threat-models --verbose\n\n" +
        "  # For compliance-focused analysis\n" +
        "  tf analyze --severity high --non-interactive\n\n" +
        
        "[bold yellow]Required Files in Project:[/bold yellow]\n" +
        "  • README.md - Project description and technologies\n" +
        "  • threats.md - Threat statements (JSON or Markdown)\n" +
        "  • architecture.* - Architecture diagrams (PNG, SVG, Mermaid)\n" +
        "  • dataflow.* - Data flow diagrams\n\n" +
        
        "[bold yellow]Environment Setup:[/bold yellow]\n" +
        "  export AWS_ACCESS_KEY_ID=your_key\n" +
        "  export AWS_SECRET_ACCESS_KEY=your_secret\n" +
        "  export AWS_DEFAULT_REGION=us-east-1\n" +
        "  # OR\n" +
        "  aws configure  # Set up AWS CLI profile\n\n" +
        
        "[dim]For more information, visit: https://github.com/your-org/threatforest[/dim]",
        title="Usage Examples",
        border_style="cyan",
        padding=(1, 2)
    )
    
    console.print(examples_panel)


def _run_analysis_workflow(
    directory: str, 
    config: ThreatForestConfig, 
    verbose: bool = False, 
    auto_approve: bool = False
) -> Dict[str, Any]:
    """
    Run the complete ThreatForest analysis workflow.
    
    Args:
        directory: Directory to analyze
        config: Configuration object
        verbose: Enable verbose output
        auto_approve: Automatically approve extracted information
        
    Returns:
        Dictionary containing analysis results and metadata
    """
    import time
    from datetime import datetime
    
    start_time = time.time()
    results = {
        'status': 'running',
        'start_time': datetime.now(),
        'directory': directory,
        'results': {},
        'errors': [],
        'error_summary': {'total_errors': 0, 'by_severity': {}},
        'duration_seconds': 0
    }
    
    # Define workflow phases
    phases = [
        "Context Detection",
        "Information Extraction", 
        "Attack Tree Generation",
        "TTC Enhancement",
        "Report Generation"
    ]
    
    # Create progress tracker
    progress, workflow_task, phase_tasks = cli_app.show_progress(phases)
    
    try:
        with progress:
            # Phase 1: Context Detection
            progress.update(phase_tasks["Context Detection"], visible=True)
            cli_app.update_phase_progress(progress, phase_tasks, "Context Detection", 20, "Scanning directory...")
            
            # Simulate context detection (replace with actual implementation)
            context_files = _simulate_context_detection(directory, config)
            results['results']['context_files'] = context_files
            
            cli_app.update_phase_progress(progress, phase_tasks, "Context Detection", 100, f"Found {len(context_files)} files")
            progress.advance(workflow_task)
            
            # Phase 2: Information Extraction
            progress.update(phase_tasks["Information Extraction"], visible=True)
            cli_app.update_phase_progress(progress, phase_tasks, "Information Extraction", 30, "Processing context files...")
            
            # Simulate information extraction
            context_info = _simulate_information_extraction(context_files, config)
            
            cli_app.update_phase_progress(progress, phase_tasks, "Information Extraction", 70, "Validating extracted information...")
            
            # User validation (if interactive)
            if not auto_approve:
                context_info = cli_app.validate_extracted_information(context_info)
            else:
                context_info.validation_status = "auto_approved"
            
            results['results']['context_information'] = context_info
            cli_app.update_phase_progress(progress, phase_tasks, "Information Extraction", 100, "Information validated")
            progress.advance(workflow_task)
            
            # Phase 3: Attack Tree Generation
            progress.update(phase_tasks["Attack Tree Generation"], visible=True)
            cli_app.update_phase_progress(progress, phase_tasks, "Attack Tree Generation", 40, "Generating attack trees...")
            
            # Simulate attack tree generation
            attack_trees = _simulate_attack_tree_generation(context_files, context_info, config)
            results['results']['attack_trees'] = attack_trees
            
            cli_app.update_phase_progress(progress, phase_tasks, "Attack Tree Generation", 100, f"Generated {len(attack_trees)} attack trees")
            progress.advance(workflow_task)
            
            # Phase 4: TTC Enhancement
            progress.update(phase_tasks["TTC Enhancement"], visible=True)
            cli_app.update_phase_progress(progress, phase_tasks, "TTC Enhancement", 60, "Enhancing with threat intelligence...")
            
            # Simulate TTC enhancement
            enhanced_trees = _simulate_ttc_enhancement(attack_trees, config)
            results['results']['attack_trees'] = enhanced_trees
            
            cli_app.update_phase_progress(progress, phase_tasks, "TTC Enhancement", 100, "Enhancement complete")
            progress.advance(workflow_task)
            
            # Phase 5: Report Generation
            progress.update(phase_tasks["Report Generation"], visible=True)
            cli_app.update_phase_progress(progress, phase_tasks, "Report Generation", 80, "Generating summary report...")
            
            # Simulate report generation
            summary_file = _simulate_report_generation(results, config)
            results['results']['summary_file'] = summary_file
            
            cli_app.update_phase_progress(progress, phase_tasks, "Report Generation", 100, "Report generated")
            progress.advance(workflow_task)
            
            # Complete workflow
            results['status'] = 'completed'
            results['duration_seconds'] = time.time() - start_time
            
            if verbose:
                console.print(f"\n[green]✅ Workflow completed successfully in {results['duration_seconds']:.1f} seconds[/green]")
    
    except Exception as e:
        results['status'] = 'failed'
        results['duration_seconds'] = time.time() - start_time
        results['errors'].append({
            'type': type(e).__name__,
            'message': str(e),
            'phase': 'workflow_execution'
        })
        results['error_summary']['total_errors'] = len(results['errors'])
        raise
    
    return results


def _simulate_context_detection(directory: str, config: ThreatForestConfig) -> List[Dict[str, Any]]:
    """Simulate context file detection (replace with actual implementation)."""
    import glob
    
    dir_path = Path(directory)
    context_files = []
    
    for pattern in config.files.context_patterns:
        matches = list(dir_path.glob(pattern))
        for match in matches:
            if match.is_file():
                context_files.append({
                    'path': str(match),
                    'type': _classify_file_type(match.name),
                    'size': match.stat().st_size,
                    'modified': match.stat().st_mtime
                })
    
    return context_files


def _classify_file_type(filename: str) -> str:
    """Classify file type based on filename."""
    filename_lower = filename.lower()
    
    if 'readme' in filename_lower:
        return 'readme'
    elif 'threat' in filename_lower:
        return 'threats'
    elif any(term in filename_lower for term in ['architecture', 'arch']):
        return 'architecture'
    elif any(term in filename_lower for term in ['dataflow', 'dfd']):
        return 'dataflow'
    else:
        return 'other'


def _simulate_information_extraction(context_files: List[Dict[str, Any]], config: ThreatForestConfig) -> ContextInformation:
    """Simulate information extraction (replace with actual implementation)."""
    from .models import ContextInformation
    from datetime import datetime
    
    # Simulate extracted information based on file types
    technologies = []
    programming_languages = []
    
    for file_info in context_files:
        if file_info['type'] == 'readme':
            # Simulate technology detection from README
            technologies.extend(['Docker', 'AWS', 'Python'])
            programming_languages.extend(['Python', 'JavaScript'])
    
    return ContextInformation(
        technologies=list(set(technologies)),
        programming_languages=list(set(programming_languages)),
        sector="Technology",
        security_objectives=["Confidentiality", "Integrity", "Availability"],
        architecture_type="Microservices",
        compliance_frameworks=["SOC2"],
        extracted_from=[f['path'] for f in context_files],
        validation_status="pending",
        confidence_score=0.85,
        timestamp=datetime.now()
    )


def _simulate_attack_tree_generation(
    context_files: List[Dict[str, Any]], 
    context_info: ContextInformation, 
    config: ThreatForestConfig
) -> List[Dict[str, Any]]:
    """Simulate attack tree generation (replace with actual implementation)."""
    attack_trees = []
    
    # Simulate finding threat statements and generating trees
    threat_files = [f for f in context_files if f['type'] == 'threats']
    
    for i, threat_file in enumerate(threat_files, 1):
        attack_trees.append({
            'threat_id': f'T{i:03d}',
            'title': f'Attack Tree for Threat {i}',
            'severity': 'High',
            'file_path': f'attack_tree_T{i:03d}.mmd',
            'mermaid_content': f'graph TD\n    A[Attacker] --> B[Target System]\n    B --> C[Impact]',
            'generated_timestamp': time.time()
        })
    
    return attack_trees


def _simulate_ttc_enhancement(attack_trees: List[Dict[str, Any]], config: ThreatForestConfig) -> List[Dict[str, Any]]:
    """Simulate TTC enhancement (replace with actual implementation)."""
    # Simulate adding TTC mappings to attack trees
    for tree in attack_trees:
        tree['ttc_mappings'] = {
            'T1566': {'technique': 'Phishing', 'alignment_score': 0.92},
            'T1078': {'technique': 'Valid Accounts', 'alignment_score': 0.87}
        }
        tree['enhanced'] = True
    
    return attack_trees


def _simulate_report_generation(results: Dict[str, Any], config: ThreatForestConfig) -> str:
    """Simulate report generation (replace with actual implementation)."""
    output_dir = Path(config.output.directory)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    summary_file = output_dir / "threat_analysis_summary.md"
    
    # Generate summary content
    summary_content = f"""# ThreatForest Analysis Summary

## Analysis Overview
- **Analysis Date**: {results['start_time'].strftime('%Y-%m-%d %H:%M:%S')}
- **Directory Analyzed**: {results['directory']}
- **Duration**: {results['duration_seconds']:.1f} seconds
- **Status**: {results['status']}

## Context Files Processed
"""
    
    for file_info in results['results'].get('context_files', []):
        summary_content += f"- {file_info['path']} ({file_info['type']})\n"
    
    summary_content += f"""
## Attack Trees Generated
"""
    
    for tree in results['results'].get('attack_trees', []):
        summary_content += f"- {tree['title']} (ID: {tree['threat_id']}, Severity: {tree['severity']})\n"
    
    summary_content += f"""
## Extracted Information
- **Technologies**: {', '.join(results['results']['context_information'].technologies)}
- **Programming Languages**: {', '.join(results['results']['context_information'].programming_languages)}
- **Business Sector**: {results['results']['context_information'].sector}
- **Security Objectives**: {', '.join(results['results']['context_information'].security_objectives)}

## Files Generated
"""
    
    for tree in results['results'].get('attack_trees', []):
        summary_content += f"- {tree['file_path']}\n"
    
    # Write summary file
    summary_file.write_text(summary_content)
    
    return str(summary_file)


def _get_readme_template() -> str:
    """Get README.md template content."""
    return """# Project Name

## Overview
Brief description of your project and its purpose.

## Architecture
Describe your system architecture, including:
- Main components and services
- Data flow between components
- External dependencies
- Security boundaries

## Technologies
List the main technologies used in your project:
- Programming languages (e.g., Python, JavaScript, Java)
- Frameworks (e.g., Django, React, Spring)
- Databases (e.g., PostgreSQL, MongoDB, Redis)
- Cloud services (e.g., AWS S3, Lambda, RDS)
- Infrastructure (e.g., Docker, Kubernetes, Terraform)

## Security Considerations
Describe security-relevant aspects:
- Authentication and authorization mechanisms
- Data encryption (at rest and in transit)
- Network security controls
- Compliance requirements (e.g., GDPR, HIPAA, SOC2)

## Business Context
- Industry/sector (e.g., Healthcare, Finance, E-commerce)
- Regulatory environment
- Data sensitivity levels
- Business criticality

## Deployment
Describe how the application is deployed and operated:
- Deployment environments (dev, staging, prod)
- Infrastructure setup
- Monitoring and logging
- Backup and recovery procedures
"""


def _get_threats_template() -> str:
    """Get threats.md template content."""
    return """# Threat Statements

This file contains threat statements for automated attack tree generation.
Each threat should include severity level, threat source, prerequisites, actions, and impacts.

## High Severity Threats

### T001: Unauthorized Data Access
- **Severity**: High
- **Threat Source**: External attacker with network access
- **Prerequisites**: Application exposed to internet, weak authentication
- **Threat Action**: Exploit authentication bypass vulnerability to access sensitive data
- **Threat Impact**: Confidential customer data exposed, regulatory compliance violation
- **Impacted Assets**: Customer database, user credentials
- **Impacted Goals**: Confidentiality, Compliance

### T002: Service Disruption Attack
- **Severity**: High  
- **Threat Source**: Malicious actor or competitor
- **Prerequisites**: Public-facing services, insufficient rate limiting
- **Threat Action**: Launch distributed denial of service (DDoS) attack
- **Threat Impact**: Service unavailability, revenue loss, reputation damage
- **Impacted Assets**: Web application, API endpoints
- **Impacted Goals**: Availability, Business continuity

## Medium Severity Threats

### T003: Insider Data Misuse
- **Severity**: Medium
- **Threat Source**: Malicious insider with legitimate access
- **Prerequisites**: Excessive user privileges, insufficient monitoring
- **Threat Action**: Abuse legitimate access to exfiltrate or modify data
- **Threat Impact**: Data integrity compromise, potential data leak
- **Impacted Assets**: Internal databases, business documents
- **Impacted Goals**: Integrity, Confidentiality

## Template for New Threats

### TXXX: [Threat Name]
- **Severity**: [High/Medium/Low]
- **Threat Source**: [Description of threat actor]
- **Prerequisites**: [Conditions that enable the threat]
- **Threat Action**: [What the attacker does]
- **Threat Impact**: [Consequences of successful attack]
- **Impacted Assets**: [Systems, data, or resources affected]
- **Impacted Goals**: [CIA triad elements affected]

## Notes
- Only High severity threats will generate attack trees by default
- Use 'tf analyze --severity medium' to include medium severity threats
- Threat IDs should be unique (T001, T002, etc.)
"""


def _get_config_template() -> str:
    """Get .tf/config.yaml template content."""
    return """# ThreatForest Configuration File
# This file configures ThreatForest behavior for this project

bedrock:
  region: us-east-1
  model: anthropic.claude-3-sonnet-20240229-v1:0
  timeout_seconds: 300

processing:
  severity_threshold: high  # low, medium, high
  max_concurrent_agents: 4
  timeout_seconds: 600

output:
  directory: ./tf-output
  format: mermaid
  include_summary: true

files:
  context_patterns:
    - "README*"
    - "readme*"
    - "architecture.*"
    - "arch.*"
    - "dataflow.*"
    - "dfd.*"
    - "threats.*"
    - "threat-*"

ttc:
  aaf_bundle_path: ./aaf-bundle.json
  alignment_threshold: 0.8
  enable_enhancement: true

# Logging configuration
logging:
  level: INFO  # DEBUG, INFO, WARNING, ERROR
  file: ./tf-output/threatforest.log
  include_console: true
"""


def _convert_config_value(value: str) -> Any:
    """Convert string configuration value to appropriate type."""
    # Handle boolean values
    if value.lower() in ('true', 'yes', '1', 'on'):
        return True
    elif value.lower() in ('false', 'no', '0', 'off'):
        return False
    
    # Handle numeric values
    try:
        if '.' in value:
            return float(value)
        else:
            return int(value)
    except ValueError:
        pass
    
    # Return as string
    return value


if __name__ == '__main__':
    main()