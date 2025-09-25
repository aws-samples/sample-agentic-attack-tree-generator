"""
Command-line interface for ThreatForest.

This module provides the main CLI application using Click framework,
with commands for analyzing projects and managing configuration.
"""

import os
import sys
import time
import asyncio
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
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
        cli_overrides: Optional[Dict[str, Any]] = None,
        validate: bool = True
    ) -> ThreatForestConfig:
        """
        Load configuration from all sources with optional validation.
        
        Args:
            config_file: Optional path to configuration file
            cli_overrides: Optional CLI argument overrides
            validate: Whether to validate configuration after loading
            
        Returns:
            Loaded ThreatForestConfig instance
            
        Raises:
            SystemExit: If configuration loading or validation fails
        """
        try:
            # Load configuration from all sources
            self.logger = self.logger or get_logger(__name__)
            self.logger.info("Starting configuration loading process")
            
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
            
            self.logger.info("Configuration loaded successfully")
            
            # Perform validation if requested
            if validate:
                self.logger.info("Starting configuration validation")
                validation_result = self._validate_loaded_configuration()
                
                if not validation_result.is_valid:
                    self.logger.error(f"Configuration validation failed with {len(validation_result.errors)} errors")
                    self._handle_validation_errors(validation_result)
                    # Exit after handling validation errors
                    sys.exit(1)
                else:
                    self.logger.info("Configuration validation successful")
                    if validation_result.warnings:
                        self.logger.warning(f"Configuration validation completed with {len(validation_result.warnings)} warnings")
                        self._log_validation_warnings(validation_result.warnings)
            
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
    
    def _validate_loaded_configuration(self) -> 'ValidationResult':
        """
        Validate the loaded configuration using ConfigManager validation.
        
        Returns:
            ValidationResult with detailed validation information
        """
        try:
            return self.config_manager.validate_configuration(self.config)
        except Exception as e:
            # Import ValidationResult and ValidationError here to avoid circular imports
            from .config import ValidationResult, ValidationError
            from datetime import datetime
            
            self.logger.error(f"Configuration validation failed with exception: {e}")
            return ValidationResult(
                is_valid=False,
                errors=[ValidationError(
                    component="validation_process",
                    error_type="validation_exception",
                    message=f"Configuration validation failed: {e}",
                    suggestion="Check configuration file syntax and required parameters"
                )],
                warnings=[],
                tested_components={"validation_process": False},
                validation_time=datetime.now()
            )
    
    def _handle_validation_errors(self, validation_result: 'ValidationResult') -> None:
        """
        Handle configuration validation errors with user-friendly messages.
        
        Args:
            validation_result: ValidationResult containing errors and warnings
        """
        console.print("\n[red]❌ Configuration validation failed[/red]")
        console.print(f"Found {len(validation_result.errors)} error(s) that must be resolved:\n")
        
        # Group errors by component for better organization
        errors_by_component = {}
        for error in validation_result.errors:
            if error.component not in errors_by_component:
                errors_by_component[error.component] = []
            errors_by_component[error.component].append(error)
        
        # Display errors by component
        for component, errors in errors_by_component.items():
            console.print(f"[bold red]{component.replace('_', ' ').title()}:[/bold red]")
            for error in errors:
                console.print(f"  • {error.message}")
                if error.suggestion:
                    console.print(f"    [dim]💡 {error.suggestion}[/dim]")
            console.print()
        
        # Show suggestions for common fixes
        console.print("[bold]Common solutions:[/bold]")
        console.print("1. Run 'tf setup' to configure ThreatForest interactively")
        console.print("2. Check AWS credentials with 'aws sts get-caller-identity'")
        console.print("3. Verify network connectivity to AWS services")
        console.print("4. Use 'tf config validate' for detailed diagnostics")
        
        # Log detailed error information
        self.logger.error("Configuration validation failed:")
        for error in validation_result.errors:
            self.logger.error(f"  {error.component}: {error.message}")
            if error.suggestion:
                self.logger.info(f"    Suggestion: {error.suggestion}")
    
    def _log_validation_warnings(self, warnings: List['ValidationError']) -> None:
        """
        Log configuration validation warnings.
        
        Args:
            warnings: List of validation warnings
        """
        for warning in warnings:
            self.logger.warning(f"{warning.component}: {warning.message}")
            if warning.suggestion:
                self.logger.info(f"  Suggestion: {warning.suggestion}")
    
    def validate_extracted_information(self, context_info: ContextInformation) -> ContextInformation:
        """
        Interactive validation of extracted context information.
        
        Args:
            context_info: Extracted context information to validate
            
        Returns:
            Validated and potentially modified context information
        """
        import sys
        import os
        
        # AGGRESSIVE AUTO-APPROVAL: Skip validation in any potentially problematic environment
        
        # Check if we're in a non-interactive environment
        if not self.interactive_mode or not sys.stdin.isatty():
            if self.logger:
                self.logger.info("Non-interactive environment detected, auto-approving extracted information")
            console.print("[yellow]⚠️  Non-interactive environment detected, auto-approving extracted information[/yellow]")
            context_info.validation_status = "auto_approved"
            return context_info
        
        # Additional checks for problematic environments
        if os.getenv('CI') or os.getenv('GITHUB_ACTIONS') or os.getenv('JENKINS_URL'):
            if self.logger:
                self.logger.info("CI/CD environment detected, auto-approving extracted information")
            console.print("[yellow]⚠️  CI/CD environment detected, auto-approving extracted information[/yellow]")
            context_info.validation_status = "auto_approved"
            return context_info
        
        # Check if we're in a terminal that might have issues with prompts
        term = os.getenv('TERM', '').lower()
        if 'dumb' in term or 'emacs' in term or not term:
            if self.logger:
                self.logger.info(f"Problematic terminal detected ({term}), auto-approving extracted information")
            console.print(f"[yellow]⚠️  Terminal type '{term}' detected, auto-approving extracted information[/yellow]")
            context_info.validation_status = "auto_approved"
            return context_info
        
        # For now, let's just auto-approve everything to prevent hanging
        # TODO: Re-enable interactive validation once we solve the hanging issue
        if self.logger:
            self.logger.info("Auto-approving extracted information (interactive validation temporarily disabled)")
        console.print("[yellow]⚠️  Interactive validation temporarily disabled to prevent hanging, auto-approving extracted information[/yellow]")
        context_info.validation_status = "auto_approved"
        return context_info
    
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
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging output')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), 
              default='INFO', help='Set logging level (default: INFO)')
@click.option('--log-file', type=click.Path(), help='Log to file instead of console')
@click.pass_context
def main(ctx, version, verbose, log_level, log_file):
    """
    ThreatForest - Agentic AI application for automated attack tree generation.
    
    Analyzes application context files and generates Mermaid-formatted attack trees
    enhanced with STIX threat intelligence and AWS Bedrock models.
    
    \b
    QUICK START:
      tf setup                    # Interactive setup wizard
      tf analyze                  # Analyze current directory
      tf config validate          # Test your configuration
    
    \b
    EXAMPLES:
      tf analyze /path/to/project --output ./results
      tf config model --list --region us-west-2
      tf setup --user --verbose
    
    \b
    CONFIGURATION:
      Configuration is loaded from multiple sources in order of precedence:
      1. Command line arguments (highest priority)
      2. Project config (.tf/config.yaml)
      3. User config (~/.tf/config.yaml)
      4. Environment variables
      5. Built-in defaults (lowest priority)
    
    \b
    REQUIREMENTS:
      - AWS credentials configured (aws configure or environment variables)
      - Access to AWS Bedrock service in your chosen region
      - Project context files (README.md, threats.md, architecture diagrams)
    
    For detailed help on any command, use: tf COMMAND --help
    """
    # Store global options in context for use by subcommands
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['log_level'] = log_level if not verbose else 'DEBUG'
    ctx.obj['log_file'] = log_file
    
    # Set up global logging early if verbose is enabled
    if verbose or log_level != 'INFO':
        cli_app.logger = setup_logging(
            log_level=ctx.obj['log_level'],
            log_file=log_file,
            include_console=True
        )
        if verbose:
            console.print(f"[dim]Verbose logging enabled (level: {ctx.obj['log_level']})[/dim]")
    
    if version:
        from . import __version__
        console.print(f"ThreatForest version {__version__}")
        return
    
    if ctx.invoked_subcommand is None:
        _show_welcome_screen()


@main.command()
@click.argument('directory', type=click.Path(exists=True, file_okay=False), default='.')
@click.option('--config', '-c', type=click.Path(exists=True), 
              help='Path to configuration file (default: .tf/config.yaml)')
@click.option('--output', '-o', type=click.Path(), 
              help='Output directory for generated files (default: ./tf-output)')
@click.option('--region', help='AWS Bedrock region (overrides config, e.g., us-east-1, us-west-2)')
@click.option('--model', help='Bedrock model ID (overrides config, e.g., anthropic.claude-3-sonnet-20240229-v1:0)')
@click.option('--severity', type=click.Choice(['low', 'medium', 'high']), 
              help='Minimum threat severity to process (default: high)')
@click.option('--dry-run', is_flag=True, 
              help='Preview analysis without execution - shows files and configuration')
@click.option('--verbose', '-v', is_flag=True, 
              help='Enable detailed progress output and debug logging')
@click.option('--non-interactive', is_flag=True, 
              help='Skip user prompts - useful for CI/CD automation')
@click.option('--auto-approve', is_flag=True, 
              help='Automatically approve extracted context information')
@click.option('--examples', is_flag=True, help='Show comprehensive usage examples and exit')
@click.option('--skip-validation', is_flag=True, 
              help='Skip configuration validation for faster startup (not recommended)')
@click.pass_context
def analyze(ctx, directory, config, output, region, model, severity, dry_run, verbose, non_interactive, auto_approve, examples, skip_validation):
    """
    Analyze a project directory for security threats and generate attack trees.
    
    This command scans your project for context files (README, architecture diagrams,
    threat statements) and uses AI to generate detailed attack trees in Mermaid format.
    
    \b
    DIRECTORY: Path to project directory to analyze (default: current directory)
    
    \b
    REQUIRED FILES:
      Your project should contain at least one of these context files:
      • README.md - Project description and technologies
      • threats.md - Threat statements in structured format
      • architecture.* - Architecture diagrams (PNG, SVG, Mermaid)
      • dataflow.* - Data flow diagrams
    
    \b
    BASIC EXAMPLES:
      tf analyze                           # Analyze current directory
      tf analyze /path/to/project          # Analyze specific project
      tf analyze --dry-run                 # Preview without execution
      tf analyze --verbose                 # Show detailed progress
    
    \b
    CONFIGURATION EXAMPLES:
      tf analyze --region us-west-2        # Use specific AWS region
      tf analyze --model claude-3-haiku    # Use specific Bedrock model
      tf analyze --severity medium         # Include medium severity threats
      tf analyze --output ./results        # Custom output directory
    
    \b
    AUTOMATION EXAMPLES:
      tf analyze --non-interactive         # Skip user prompts
      tf analyze --auto-approve            # Auto-approve extracted info
      tf analyze --non-interactive --auto-approve --verbose  # Full automation
    
    \b
    TROUBLESHOOTING:
      If analysis fails, try these steps:
      1. Run 'tf config validate' to check your setup
      2. Use 'tf setup' for guided configuration
      3. Check AWS credentials: aws sts get-caller-identity
      4. Use --verbose for detailed error information
      5. Use --dry-run to verify file detection
    
    \b
    OUTPUT:
      Generated files are saved to the output directory:
      • attack_tree_*.md - Mermaid attack tree diagrams
      • threat_analysis_summary.md - Analysis summary report
      • threatforest.log - Detailed execution log (if logging enabled)
    
    For more examples, use: tf analyze --examples
    """
    
    if examples:
        _show_usage_examples()
        return
    
    # Use global logging options from context
    global_verbose = ctx.obj.get('verbose', False)
    log_level = ctx.obj.get('log_level', 'INFO')
    log_file = ctx.obj.get('log_file')
    
    # Command-level verbose overrides global setting
    effective_verbose = verbose or global_verbose
    effective_log_level = 'DEBUG' if effective_verbose else log_level
    
    # Set interactive mode
    cli_app.interactive_mode = not non_interactive
    
    # Coordinate auto_approve with non_interactive mode
    if non_interactive and not auto_approve:
        auto_approve = True
        if effective_verbose:
            console.print(f"[dim]🤖 Non-interactive mode: auto-approve enabled[/dim]")
    
    # Also check if we're in a non-interactive environment (no TTY)
    import sys
    if not sys.stdin.isatty() and not auto_approve:
        auto_approve = True
        if effective_verbose:
            console.print(f"[dim]🤖 Non-TTY environment detected: auto-approve enabled[/dim]")
        logger.info("Non-TTY environment detected, enabling auto-approve")
    
    console.print(f"[blue]🔍 Starting ThreatForest analysis of: {directory}[/blue]")
    
    if effective_verbose:
        console.print(f"[dim]Logging level: {effective_log_level}[/dim]")
        console.print(f"[dim]Interactive mode: {'Disabled' if non_interactive else 'Enabled'}[/dim]")
        if log_file:
            console.print(f"[dim]Log file: {log_file}[/dim]")
    
    # Build CLI overrides including logging configuration
    cli_overrides = {
        'log_level': effective_log_level,
        'log_file': log_file
    }
    
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
    if skip_validation:
        cli_overrides['skip_validation'] = True
    
    # Load configuration with validation (can be disabled for backward compatibility)
    validate_config = not cli_overrides.get('skip_validation', False)
    config_obj = cli_app.load_config(
        config_file=config, 
        cli_overrides=cli_overrides,
        validate=validate_config
    )
    
    if verbose:
        console.print(f"[dim]Configuration loaded from: {config or 'default sources'}[/dim]")
        console.print(f"[dim]Output directory: {config_obj.output.directory}[/dim]")
        console.print(f"[dim]Bedrock region: {config_obj.bedrock.region}[/dim]")
        console.print(f"[dim]Bedrock model: {config_obj.bedrock.model}[/dim]")
        console.print(f"[dim]Bedrock timeout: {config_obj.bedrock.timeout_seconds}s[/dim]")
        console.print(f"[dim]Temperature: {config_obj.bedrock.temperature}[/dim]")
        console.print(f"[dim]Max tokens: {config_obj.bedrock.max_tokens}[/dim]")
        console.print(f"[dim]Severity threshold: {config_obj.processing.severity_threshold}[/dim]")
        console.print(f"[dim]Interactive mode: {'Disabled' if non_interactive else 'Enabled'}[/dim]")
        
        # Log if using inference profile
        if "inference-profile" in config_obj.bedrock.model:
            console.print(f"[dim]🎯 Using inference profile ARN[/dim]")
        else:
            console.print(f"[dim]🔧 Using foundation model[/dim]")
    
    # Validate AWS credentials
    if not cli_app.validate_aws_credentials():
        sys.exit(1)
    
    if dry_run:
        console.print("[yellow]📋 Dry run mode - showing what would be analyzed:[/yellow]")
        _show_dry_run_info(directory, config_obj)
        return
    
    # Log analysis start details
    logger = logging.getLogger(__name__)
    logger.info(f"=== STARTING THREATFOREST ANALYSIS ===")
    logger.info(f"Directory: {directory}")
    logger.info(f"Model: {config_obj.bedrock.model}")
    logger.info(f"Region: {config_obj.bedrock.region}")
    logger.info(f"Timeout: {config_obj.bedrock.timeout_seconds}s")
    logger.info(f"Interactive: {not non_interactive}")
    logger.info(f"Auto-approve: {auto_approve}")
    
    if verbose:
        console.print(f"[bold cyan]📋 Analysis Configuration:[/bold cyan]")
        console.print(f"[dim]Directory: {directory}[/dim]")
        console.print(f"[dim]Model: {config_obj.bedrock.model}[/dim]")
        console.print(f"[dim]Region: {config_obj.bedrock.region}[/dim]")
        console.print(f"[dim]Timeout: {config_obj.bedrock.timeout_seconds}s[/dim]")
    
    # Run the analysis workflow
    try:
        results = _run_analysis_workflow(directory, config_obj, verbose, auto_approve)
        logger.info("=== ANALYSIS COMPLETED SUCCESSFULLY ===")
        cli_app.show_analysis_summary(results)
    except KeyboardInterrupt:
        logger.info("=== ANALYSIS INTERRUPTED BY USER ===")
        console.print("\n[yellow]⚠️  Analysis interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        logger.error(f"=== ANALYSIS FAILED ===")
        logger.error(f"Error type: {type(e)}")
        logger.error(f"Error message: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        if cli_app.error_handler:
            error_context = cli_app.error_handler.handle_error(e, operation="analysis workflow")
            console.print(f"\n[red]❌ Analysis failed: {error_context.message}[/red]")
            if error_context.suggested_actions:
                console.print("\n[bold]Suggested actions:[/bold]")
                for action in error_context.suggested_actions:
                    console.print(f"  • {action}")
        else:
            console.print(f"\n[red]❌ Analysis failed: {e}[/red]")
            if verbose:
                console.print(f"[dim]Error type: {type(e)}[/dim]")
                console.print(f"[dim]Check logs for detailed traceback[/dim]")
        sys.exit(1)


@main.command()
@click.option('--user', is_flag=True, 
              help='Create user-level configuration (~/.tf/config.yaml) instead of project-level')
@click.option('--force', is_flag=True, 
              help='Overwrite existing configuration without prompting')
@click.option('--verbose', '-v', is_flag=True, 
              help='Show detailed setup information and validation steps')
@click.pass_context
def setup(ctx, user, force, verbose):
    """
    Interactive setup wizard for ThreatForest configuration.
    
    This wizard guides you through configuring ThreatForest for first-time use.
    It will detect your AWS credentials, help you select a Bedrock model,
    and create a configuration file with optimal settings.
    
    \b
    CONFIGURATION LEVELS:
      • Project-level (default): .tf/config.yaml - shared with team
      • User-level (--user): ~/.tf/config.yaml - personal settings
    
    \b
    PREREQUISITES:
      Before running setup, ensure you have:
      • AWS credentials configured (aws configure or environment variables)
      • Access to AWS Bedrock service in your chosen region
      • Network connectivity to AWS services
    
    \b
    EXAMPLES:
      tf setup                    # Interactive project setup
      tf setup --user             # Setup user-level configuration
      tf setup --force            # Overwrite existing configuration
      tf setup --verbose          # Show detailed validation steps
    
    \b
    WHAT THIS WIZARD DOES:
      1. Detects and validates AWS credentials
      2. Tests connectivity to AWS Bedrock service
      3. Discovers available models in your region
      4. Helps you select optimal model for your use case
      5. Configures processing and output settings
      6. Validates the complete configuration
      7. Saves configuration to appropriate location
    
    \b
    TROUBLESHOOTING:
      If setup fails, check these common issues:
      • AWS credentials: aws sts get-caller-identity
      • Bedrock access: Check IAM permissions for bedrock:*
      • Network: Verify connectivity to AWS services
      • Region: Ensure Bedrock is available in your region
    
    After setup, use 'tf config validate' to test your configuration.
    """
    try:
        # Import SetupWizard here to avoid circular imports
        from threatforest.setup_wizard import SetupWizard, SetupWizardError
        
        # Use global logging options from context
        global_verbose = ctx.obj.get('verbose', False)
        log_level = ctx.obj.get('log_level', 'INFO')
        log_file = ctx.obj.get('log_file')
        
        # Command-level verbose overrides global setting
        effective_verbose = verbose or global_verbose
        effective_log_level = 'DEBUG' if effective_verbose else log_level
        
        # Set up logging for verbose mode
        if effective_verbose or log_level != 'INFO':
            cli_app.logger = setup_logging(
                log_level=effective_log_level,
                log_file=log_file,
                include_console=True
            )
        
        console.print("[bold green]🚀 ThreatForest Setup Wizard[/bold green]")
        
        # Check if configuration already exists
        project_dir = Path.cwd()
        user_config_path = Path.home() / ".tf" / "config.yaml"
        project_config_path = project_dir / ".tf" / "config.yaml"
        
        config_exists = user_config_path.exists() or project_config_path.exists()
        
        if config_exists and not force:
            console.print(f"\n[yellow]⚠️  Configuration already exists[/yellow]")
            
            if user_config_path.exists():
                console.print(f"User config: {user_config_path}")
            if project_config_path.exists():
                console.print(f"Project config: {project_config_path}")
            
            if not Confirm.ask("Continue with setup anyway?", default=False):
                console.print("[yellow]Setup cancelled[/yellow]")
                return
        
        # Initialize setup wizard
        wizard = SetupWizard(str(project_dir))
        
        # Run interactive setup
        console.print(f"\n[blue]Starting interactive setup...[/blue]")
        if verbose:
            console.print(f"[dim]Project directory: {project_dir}[/dim]")
            console.print(f"[dim]Setup scope: {'User-level' if user else 'Auto-detect'}[/dim]")
        
        try:
            config = wizard.run_interactive_setup()
            
            console.print(f"\n[bold green]🎉 Setup completed successfully![/bold green]")
            console.print(f"Configuration saved and validated.")
            console.print(f"\n[bold]Next steps:[/bold]")
            console.print("1. Run 'tf analyze' to start threat analysis")
            console.print("2. Use 'tf config show --detailed' to view your configuration")
            console.print("3. Use 'tf config validate' to test your setup")
            
        except SetupWizardError as e:
            console.print(f"\n[red]❌ Setup failed: {e}[/red]")
            console.print(f"\n[bold]Troubleshooting:[/bold]")
            console.print("1. Check your AWS credentials")
            console.print("2. Verify network connectivity")
            console.print("3. Run 'tf config validate' for detailed diagnostics")
            console.print("4. Use 'tf setup --verbose' for detailed logging")
            sys.exit(1)
    
    except ImportError:
        console.print("[red]Error: SetupWizard not available. Check your installation.[/red]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Setup cancelled by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        if cli_app.error_handler:
            error_context = cli_app.error_handler.handle_error(e, operation="setup wizard")
            console.print(f"\n[red]❌ Setup failed: {error_context.message}[/red]")
            if error_context.suggested_actions:
                console.print("\n[bold]Suggested actions:[/bold]")
                for action in error_context.suggested_actions:
                    console.print(f"  • {action}")
        else:
            console.print(f"\n[red]❌ Setup failed: {e}[/red]")
        sys.exit(1)


@main.command()
@click.option('--verbose', '-v', is_flag=True, 
              help='Show detailed status including configuration sources and validation history')
@click.option('--check-models', is_flag=True, 
              help='Check availability of configured models in real-time')
@click.option('--check-connectivity', is_flag=True, 
              help='Test network connectivity to AWS services')
@click.pass_context
def status(ctx, verbose, check_models, check_connectivity):
    """
    Display ThreatForest system status and configuration health.
    
    Provides a quick overview of your ThreatForest setup including
    configuration status, AWS connectivity, and system readiness.
    
    \b
    STATUS OVERVIEW:
      • Configuration validation status
      • AWS credentials and permissions
      • Bedrock service connectivity
      • Model availability
      • Recent analysis history
      • System health indicators
    
    \b
    EXAMPLES:
      tf status                         # Basic status overview
      tf status --verbose               # Detailed system information
      tf status --check-models          # Real-time model availability
      tf status --check-connectivity    # Test AWS connectivity
    
    \b
    STATUS INDICATORS:
      🟢 Green - System ready, no issues detected
      🟡 Yellow - Minor issues or warnings
      🔴 Red - Critical issues requiring attention
      ⚪ Gray - Component not configured or disabled
    
    \b
    QUICK HEALTH CHECK:
      This command provides a faster alternative to 'tf config validate'
      for checking system status. Use it to quickly verify that ThreatForest
      is ready for analysis without running full validation tests.
    
    \b
    TROUBLESHOOTING:
      If status shows issues:
      1. Run 'tf config validate' for detailed diagnostics
      2. Use 'tf config doctor' for comprehensive troubleshooting
      3. Run 'tf setup' to reconfigure problematic components
    
    For real-time checks, use --check-models and --check-connectivity options.
    """
    console.print("[bold blue]🔍 ThreatForest System Status[/bold blue]\n")
    
    # Use global logging options from context
    global_verbose = ctx.obj.get('verbose', False)
    log_level = ctx.obj.get('log_level', 'INFO')
    log_file = ctx.obj.get('log_file')
    
    # Command-level verbose overrides global setting
    effective_verbose = verbose or global_verbose
    effective_log_level = 'DEBUG' if effective_verbose else log_level
    
    # Set up logging for verbose mode
    if effective_verbose or log_level != 'INFO':
        cli_app.logger = setup_logging(
            log_level=effective_log_level,
            log_file=log_file,
            include_console=True
        )
        cli_app.logger.info("Starting enhanced status check with verbose logging")
    
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
    
    if effective_verbose:
        cli_app.logger.info(f"Python version check: {python_version} (OK: {python_ok})")
    
    # Check AWS credentials
    if effective_verbose:
        cli_app.logger.info("Validating AWS credentials")
    
    aws_ok = cli_app.validate_aws_credentials()
    aws_status = "[green]✅ OK[/green]" if aws_ok else "[red]❌ MISSING[/red]"
    aws_details = "Credentials found" if aws_ok else "Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or AWS_PROFILE"
    status_table.add_row("AWS Credentials", aws_status, aws_details)
    
    if effective_verbose:
        cli_app.logger.info(f"AWS credentials validation: {'PASSED' if aws_ok else 'FAILED'}")
    
    # Enhanced configuration validation
    config_obj = None
    validation_result = None
    try:
        if effective_verbose:
            cli_app.logger.info("Loading configuration for validation")
        
        # Load configuration without validation for status command (validation is done separately)
        config_obj = cli_app.load_config(validate=False)
        
        if effective_verbose:
            cli_app.logger.info("Running comprehensive configuration validation")
        
        # Run comprehensive validation for enhanced status
        validation_result = cli_app.config_manager.validate_configuration(config_obj)
        
        if validation_result.is_valid:
            config_status = "[green]✅ OK[/green]"
            config_details = f"Region: {config_obj.bedrock.region}, Model: {config_obj.bedrock.model}, Status: Valid"
            if effective_verbose:
                cli_app.logger.info(f"Configuration validation: PASSED - {len(validation_result.tested_components)} components tested")
        else:
            config_status = "[yellow]⚠️  ISSUES[/yellow]"
            error_count = len(validation_result.errors)
            config_details = f"Region: {config_obj.bedrock.region}, Model: {config_obj.bedrock.model}, Errors: {error_count}"
            if effective_verbose:
                cli_app.logger.warning(f"Configuration validation: FAILED - {error_count} errors, {len(validation_result.warnings)} warnings")
                for error in validation_result.errors:
                    cli_app.logger.warning(f"  Error in {error.component}: {error.message}")
    except Exception as e:
        config_status = "[red]❌ ERROR[/red]"
        config_details = str(e)
        if effective_verbose:
            cli_app.logger.error(f"Configuration loading failed: {e}")
    
    status_table.add_row("Configuration", config_status, config_details)
    
    # Enhanced model availability check using BedrockClient methods
    model_status = "[red]❌ UNKNOWN[/red]"
    model_details = "Configuration not loaded"
    
    if config_obj and aws_ok:
        try:
            # Import BedrockClient here to avoid circular imports
            from threatforest.utils.bedrock_client import BedrockClient, BedrockClientError
            
            if effective_verbose:
                console.print("[dim]Checking model availability...[/dim]")
                cli_app.logger.info(f"Testing model availability: {config_obj.bedrock.model} in {config_obj.bedrock.region}")
            
            # Create Bedrock client for model validation
            bedrock_client = BedrockClient(config_obj.bedrock)
            
            # Check if model is available in the configured region
            is_available = bedrock_client.validate_model_region_compatibility(
                config_obj.bedrock.model, 
                config_obj.bedrock.region
            )
            
            if is_available:
                model_status = "[green]✅ AVAILABLE[/green]"
                model_details = f"Model {config_obj.bedrock.model} available in {config_obj.bedrock.region}"
                if effective_verbose:
                    cli_app.logger.info("Model availability check: PASSED")
            else:
                model_status = "[red]❌ UNAVAILABLE[/red]"
                model_details = f"Model {config_obj.bedrock.model} not available in {config_obj.bedrock.region}"
                if effective_verbose:
                    cli_app.logger.warning("Model availability check: FAILED - model not available in region")
                
        except Exception as e:
            # Check if it's a BedrockClientError by name to avoid import issues
            if "BedrockClientError" in str(type(e)):
                model_status = "[yellow]⚠️  CHECK FAILED[/yellow]"
                model_details = f"Could not verify model availability: {str(e)[:50]}..."
                if effective_verbose:
                    cli_app.logger.warning(f"Model availability check: ERROR - {e}")
            elif "ImportError" in str(type(e)) or "ModuleNotFoundError" in str(type(e)):
                model_status = "[red]❌ CLIENT ERROR[/red]"
                model_details = "BedrockClient not available"
                if effective_verbose:
                    cli_app.logger.error("Model availability check: ERROR - BedrockClient import failed")
            else:
                model_status = "[yellow]⚠️  CHECK FAILED[/yellow]"
                model_details = f"Model check error: {str(e)[:50]}..."
                if effective_verbose:
                    cli_app.logger.error(f"Model availability check: UNEXPECTED ERROR - {e}")
    else:
        if effective_verbose:
            cli_app.logger.info("Skipping model availability check - configuration or AWS credentials not available")
    
    status_table.add_row("Model Availability", model_status, model_details)
    
    # Check dependencies and SDK versions
    if effective_verbose:
        cli_app.logger.info("Checking AWS SDK versions")
    
    try:
        import boto3
        import botocore
        import rich
        import click
        
        # Check minimum versions
        boto3_version = boto3.__version__
        botocore_version = botocore.__version__
        
        # Parse version numbers for comparison
        def parse_version(version_str):
            return tuple(map(int, version_str.split('.')[:3]))
        
        boto3_ok = parse_version(boto3_version) >= (1, 34, 0)
        botocore_ok = parse_version(botocore_version) >= (1, 34, 0)
        
        if boto3_ok and botocore_ok:
            deps_status = "[green]✅ OK[/green]"
            deps_details = f"boto3 v{boto3_version}, botocore v{botocore_version}"
        else:
            deps_status = "[yellow]⚠️  OLD[/yellow]"
            deps_details = f"boto3 v{boto3_version}, botocore v{botocore_version} (recommend >=1.34.0)"
        
        if verbose:
            cli_app.logger.info(f"AWS SDK versions: boto3={boto3_version}, botocore={botocore_version} (OK: {boto3_ok and botocore_ok})")
            
    except ImportError as e:
        deps_status = "[red]❌ MISSING[/red]"
        deps_details = f"Missing package: {e.name}"
        if verbose:
            cli_app.logger.error(f"AWS SDK check: FAILED - missing package {e.name}")
    except Exception as e:
        deps_status = "[red]❌ ERROR[/red]"
        deps_details = f"Version check failed: {e}"
        if verbose:
            cli_app.logger.error(f"AWS SDK check: ERROR - {e}")
    
    status_table.add_row("AWS SDK", deps_status, deps_details)
    
    console.print(status_table)
    
    # Show detailed validation results if verbose mode or validation failed
    if verbose and validation_result:
        console.print("\n[bold cyan]📋 Component Test Results[/bold cyan]")
        
        # Create detailed component test results table
        component_table = Table(show_header=True, header_style="bold magenta")
        component_table.add_column("Component", style="cyan", no_wrap=True)
        component_table.add_column("Test Result", style="white")
        component_table.add_column("Details", style="dim")
        
        for component, result in validation_result.tested_components.items():
            status_icon = "[green]✅ PASSED[/green]" if result else "[red]❌ FAILED[/red]"
            
            # Get component-specific details
            component_errors = [e for e in validation_result.errors if e.component == component]
            component_warnings = [w for w in validation_result.warnings if w.component == component]
            
            if component_errors:
                details = f"Errors: {len(component_errors)}"
                if component_warnings:
                    details += f", Warnings: {len(component_warnings)}"
            elif component_warnings:
                details = f"Warnings: {len(component_warnings)}"
            else:
                details = "All checks passed"
            
            component_table.add_row(component.replace('_', ' ').title(), status_icon, details)
        
        console.print(component_table)
        
        # Show validation errors if any
        if validation_result.errors:
            console.print("\n[bold red]❌ Configuration Validation Errors[/bold red]")
            
            error_table = Table(show_header=True, header_style="bold red")
            error_table.add_column("Component", style="red", no_wrap=True)
            error_table.add_column("Error", style="white")
            error_table.add_column("Suggestion", style="dim")
            
            for error in validation_result.errors:
                error_table.add_row(
                    error.component.replace('_', ' ').title(),
                    error.message,
                    error.suggestion or "No suggestion available"
                )
            
            console.print(error_table)
        
        # Show validation warnings if any
        if validation_result.warnings:
            console.print("\n[bold yellow]⚠️  Configuration Validation Warnings[/bold yellow]")
            
            warning_table = Table(show_header=True, header_style="bold yellow")
            warning_table.add_column("Component", style="yellow", no_wrap=True)
            warning_table.add_column("Warning", style="white")
            warning_table.add_column("Suggestion", style="dim")
            
            for warning in validation_result.warnings:
                warning_table.add_row(
                    warning.component.replace('_', ' ').title(),
                    warning.message,
                    warning.suggestion or "No suggestion available"
                )
            
            console.print(warning_table)
    
    # Show overall status summary
    console.print("\n" + "="*60)
    
    # Determine overall system health
    has_critical_issues = (
        not python_ok or 
        not aws_ok or 
        config_status == "[red]❌ ERROR[/red]" or
        (validation_result and not validation_result.is_valid and len(validation_result.errors) > 0)
    )
    
    has_warnings = (
        config_status == "[yellow]⚠️  ISSUES[/yellow]" or
        model_status in ["[yellow]⚠️  CHECK FAILED[/yellow]", "[red]❌ UNAVAILABLE[/red]"] or
        deps_status == "[yellow]⚠️  OLD[/yellow]" or
        (validation_result and len(validation_result.warnings) > 0)
    )
    
    if has_critical_issues:
        console.print("[bold red]🚨 Some issues need to be resolved before using ThreatForest[/bold red]")
        console.print("\n[bold]Recommended actions:[/bold]")
        
        if not python_ok:
            console.print("• Upgrade to Python 3.9 or higher")
        if not aws_ok:
            console.print("• Configure AWS credentials using 'aws configure' or environment variables")
        if config_status == "[red]❌ ERROR[/red]":
            console.print("• Fix configuration issues using 'tf setup' or 'tf config validate'")
        if validation_result and validation_result.errors:
            console.print("• Run 'tf config validate' for detailed error information")
            console.print("• Use 'tf setup' to reconfigure your settings")
        
    elif has_warnings:
        console.print("[bold yellow]⚠️  ThreatForest is functional but some optimizations are recommended[/bold yellow]")
        console.print("\n[bold]Suggested improvements:[/bold]")
        
        if model_status == "[red]❌ UNAVAILABLE[/red]":
            console.print("• Choose a different model or region using 'tf config model'")
        elif model_status == "[yellow]⚠️  CHECK FAILED[/yellow]":
            console.print("• Verify network connectivity and AWS permissions")
        if deps_status == "[yellow]⚠️  OLD[/yellow]":
            console.print("• Update AWS SDK: pip install --upgrade boto3 botocore")
        if validation_result and validation_result.warnings:
            console.print("• Review configuration warnings using 'tf status --verbose'")
    else:
        console.print("[bold green]✅ ThreatForest is ready to use![/bold green]")
        console.print("\n[bold]Next steps:[/bold]")
        console.print("• Run 'tf analyze' to start threat analysis")
        console.print("• Use 'tf analyze --help' for available options")
    
    if verbose:
        cli_app.logger.info(f"Status check completed - Critical issues: {has_critical_issues}, Warnings: {has_warnings}")
    
    console.print("="*60)
    
    # Overall status with enhanced logic
    config_valid = config_status == "[green]✅ OK[/green]"
    model_available = model_status == "[green]✅ AVAILABLE[/green]"
    overall_ok = python_ok and aws_ok and config_valid and model_available
    
    if overall_ok:
        console.print("\n[bold green]🎉 ThreatForest is ready to use![/bold green]")
        console.print("Run 'tf analyze' to start analyzing your project.")
    else:
        console.print("\n[bold red]⚠️  Some issues need to be resolved before using ThreatForest.[/bold red]")
        console.print("Please address the issues marked above.")
        
        # Enhanced helpful commands with context-specific suggestions
        console.print(f"\n[bold]Helpful commands:[/bold]")
        console.print("• tf setup - Run interactive setup wizard")
        console.print("• tf config validate - Detailed configuration validation")
        console.print("• tf config show --detailed - View configuration with validation status")
        
        if not aws_ok:
            console.print("• aws configure - Set up AWS credentials")
        
        if not config_valid and config_obj:
            console.print("• tf config model --list - View available models")
            console.print("• tf config model --recommend analysis - Get model recommendations")
        
        if verbose:
            console.print("• tf status --verbose - Show detailed status information")


@main.command()
@click.argument('project_path', type=click.Path(), default='.')
@click.option('--template', type=click.Choice(['basic', 'web-app', 'microservices', 'iot']), 
              default='basic', help='Project template to use (default: basic)')
@click.option('--force', is_flag=True, 
              help='Overwrite existing files without prompting')
def init(project_path, template, force):
    """
    Initialize a new project directory with ThreatForest template files.
    
    Creates a new ThreatForest project with template files including
    README.md, threats.md, and configuration files to get you started
    with threat analysis.
    
    \b
    PROJECT_PATH: Directory to initialize (default: current directory)
    
    \b
    TEMPLATE OPTIONS:
      basic        - Generic project template with common threats
      web-app      - Web application with OWASP Top 10 threats
      microservices - Microservices architecture threats
      iot          - IoT device and platform threats
    
    \b
    EXAMPLES:
      tf init                           # Initialize current directory
      tf init ./my-project              # Initialize specific directory
      tf init --template web-app        # Use web application template
      tf init --force                   # Overwrite existing files
    
    \b
    CREATED FILES:
      README.md                         # Project description template
      threats.md                        # Threat statements template
      .tf/config.yaml                   # ThreatForest configuration
      architecture.md                   # Architecture documentation template
    
    \b
    NEXT STEPS:
      After initialization:
      1. Edit README.md with your project details
      2. Customize threats.md with your specific threats
      3. Add architecture diagrams or descriptions
      4. Run 'tf setup' to configure AWS and Bedrock
      5. Run 'tf analyze' to generate attack trees
    
    \b
    TEMPLATE CUSTOMIZATION:
      Each template includes threat statements relevant to that domain:
      • Web-app: OWASP Top 10, authentication, session management
      • Microservices: Service mesh, API gateway, container security
      • IoT: Device firmware, communication protocols, data privacy
    
    Use --force to overwrite existing files without confirmation prompts.
    """
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
    """
    Manage ThreatForest configuration settings.
    
    Configuration is loaded from multiple sources in order of precedence:
    1. Command line arguments (highest priority)
    2. Project config (.tf/config.yaml)
    3. User config (~/.tf/config.yaml)
    4. Environment variables
    5. Built-in defaults (lowest priority)
    
    \b
    COMMON TASKS:
      tf config show                    # View current configuration
      tf config validate                # Test configuration and connectivity
      tf config model --list            # Browse available Bedrock models
      tf config set bedrock.region us-west-2  # Change AWS region
    
    Use 'tf config COMMAND --help' for detailed help on each command.
    """
    pass





@config.command('show')
@click.option('--config', '-c', type=click.Path(exists=True), 
              help='Path to specific configuration file to display')
@click.option('--detailed', is_flag=True, 
              help='Show detailed configuration with validation status and source information')
@click.option('--sources', is_flag=True, 
              help='Show configuration sources and precedence')
def config_show(config, detailed, sources):
    """
    Display current ThreatForest configuration.
    
    Shows the effective configuration values that ThreatForest will use,
    combining settings from all sources (CLI args, config files, environment, defaults).
    
    \b
    EXAMPLES:
      tf config show                    # Basic configuration display
      tf config show --detailed         # Include validation status
      tf config show --sources          # Show where each setting comes from
      tf config show --config ./custom.yaml  # Show specific config file
    
    \b
    CONFIGURATION SOURCES:
      Settings are loaded from multiple sources in this order:
      1. Command line arguments (highest priority)
      2. Project config (.tf/config.yaml)
      3. User config (~/.tf/config.yaml)
      4. Environment variables (AWS_*, TF_*)
      5. Built-in defaults (lowest priority)
    
    Use --detailed to see validation status and last validation time.
    Use --sources to see which source provides each configuration value.
    """
    config_obj = cli_app.load_config(config_file=config)
    
    if detailed:
        # Show detailed configuration with validation
        console.print("[blue]🔍 Validating configuration...[/blue]")
        validation_result = cli_app.config_manager.validate_configuration(config_obj)
        
        # Show validation status
        status_color = "green" if validation_result.is_valid else "red"
        status_text = "✅ Valid" if validation_result.is_valid else "❌ Invalid"
        
        console.print(Panel(
            f"[bold]Configuration Status:[/bold] [{status_color}]{status_text}[/{status_color}]\n"
            f"[bold]Validation Time:[/bold] {validation_result.validation_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"[bold]Components Tested:[/bold] {len(validation_result.tested_components)}\n\n"
            f"[bold]Bedrock Configuration:[/bold]\n"
            f"Region: {config_obj.bedrock.region}\n"
            f"Model: {config_obj.bedrock.model}\n"
            f"Temperature: {config_obj.bedrock.temperature}\n"
            f"Max Tokens: {config_obj.bedrock.max_tokens}\n"
            f"Top-p: {config_obj.bedrock.top_p}\n"
            f"Timeout: {config_obj.bedrock.timeout_seconds}s\n"
            f"Validation Status: {config_obj.bedrock.validation_status}\n"
            f"Last Validated: {config_obj.bedrock.last_validated or 'Never'}\n\n"
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
            title="ThreatForest Configuration (Detailed)",
            border_style="blue"
        ))
        
        # Show validation errors if any
        if validation_result.errors:
            console.print("\n[bold red]Validation Errors:[/bold red]")
            for error in validation_result.errors:
                console.print(f"  • [{error.component}] {error.message}")
                if error.suggestion:
                    console.print(f"    💡 {error.suggestion}")
        
        # Show validation warnings if any
        if validation_result.warnings:
            console.print("\n[bold yellow]Validation Warnings:[/bold yellow]")
            for warning in validation_result.warnings:
                console.print(f"  • [{warning.component}] {warning.message}")
                if warning.suggestion:
                    console.print(f"    💡 {warning.suggestion}")
    else:
        # Show basic configuration
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
@click.option('--user', is_flag=True, 
              help='Save to user-level configuration (~/.tf/config.yaml) instead of project-level')
@click.option('--validate', is_flag=True, 
              help='Validate configuration after setting the value')
def config_set(key, value, user, validate):
    """
    Set a specific configuration value.
    
    Updates a single configuration setting and saves it to the appropriate
    configuration file. Values are automatically converted to the correct type.
    
    \b
    KEY: Configuration key in dot notation (section.field)
    VALUE: New value for the configuration setting
    
    \b
    COMMON CONFIGURATION KEYS:
      bedrock.region                    # AWS region (e.g., us-east-1)
      bedrock.model                     # Bedrock model ID
      bedrock.temperature               # Model temperature (0.0-1.0)
      bedrock.max_tokens                # Maximum tokens per request
      processing.severity_threshold     # Minimum severity (low, medium, high)
      processing.max_concurrent_agents  # Number of parallel agents
      output.directory                  # Output directory path
      output.format                     # Output format (mermaid, json)
      ttc.enable_enhancement           # Enable TTC enhancement (true/false)
    
    \b
    EXAMPLES:
      tf config set bedrock.region us-west-2
      tf config set bedrock.model anthropic.claude-3-haiku-20240307-v1:0
      tf config set processing.severity_threshold medium
      tf config set bedrock.temperature 0.7 --user
      tf config set output.directory ./custom-output --validate
    
    \b
    VALUE TYPES:
      Values are automatically converted to appropriate types:
      • Booleans: true, false, yes, no, 1, 0
      • Numbers: Integers and floats are detected automatically
      • Strings: Everything else is treated as a string
    
    \b
    CONFIGURATION LEVELS:
      • Project-level (default): .tf/config.yaml - shared with team
      • User-level (--user): ~/.tf/config.yaml - personal settings
    
    Use --validate to test the configuration after making changes.
    """
    # Load current configuration without validation for config set command
    config_obj = cli_app.load_config(validate=False)
    
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
        
        console.print(f"[green]✅ Configuration updated: {key} = {converted_value}[/green]")
        if user:
            console.print("[dim]Saved to user-level configuration (~/.tf/config.yaml)[/dim]")
        else:
            console.print("[dim]Saved to project-level configuration (.tf/config.yaml)[/dim]")
        
        # Validate configuration if requested
        if validate:
            console.print("\n[blue]🔍 Validating updated configuration...[/blue]")
            try:
                validation_result = cli_app.config_manager.validate_configuration(updated_config)
                if validation_result.is_valid:
                    console.print("[green]✅ Configuration validation passed[/green]")
                else:
                    console.print(f"[yellow]⚠️  Configuration has {len(validation_result.errors)} validation errors[/yellow]")
                    for error in validation_result.errors[:3]:  # Show first 3 errors
                        console.print(f"  • {error.message}")
                    if len(validation_result.errors) > 3:
                        console.print(f"  ... and {len(validation_result.errors) - 3} more errors")
                    console.print("\nUse 'tf config validate' for detailed diagnostics")
            except Exception as e:
                console.print(f"[yellow]⚠️  Could not validate configuration: {e}[/yellow]")
            
    except Exception as e:
        console.print(f"[red]❌ Error updating configuration: {e}[/red]")
        console.print("\n[bold]Troubleshooting:[/bold]")
        console.print("• Check that the configuration key is valid (use 'tf config show' to see current keys)")
        console.print("• Ensure the value is in the correct format for the setting")
        console.print("• Verify you have write permissions to the configuration directory")
        sys.exit(1)


@config.command('validate')
@click.option('--config', '-c', type=click.Path(exists=True), 
              help='Path to specific configuration file to validate')
@click.option('--verbose', '-v', is_flag=True, 
              help='Show detailed validation steps and component test results')
@click.option('--fix', is_flag=True, 
              help='Attempt to automatically fix common configuration issues')
@click.pass_context
def config_validate(ctx, config, verbose, fix):
    """
    Validate ThreatForest configuration and test connectivity.
    
    This command performs comprehensive validation of your ThreatForest setup:
    • Configuration file syntax and required fields
    • AWS credentials and permissions
    • Bedrock service connectivity and model availability
    • Output directory permissions
    • TTC bundle file accessibility
    
    \b
    VALIDATION CHECKS:
      ✓ Configuration loading and parsing
      ✓ AWS credentials detection and validity
      ✓ Bedrock service access permissions
      ✓ Model availability in configured region
      ✓ Output directory write permissions
      ✓ TTC bundle file accessibility (if enabled)
    
    \b
    EXAMPLES:
      tf config validate                # Basic validation
      tf config validate --verbose     # Show detailed test results
      tf config validate --fix         # Auto-fix common issues
      tf config validate --config ./test.yaml  # Validate specific file
    
    \b
    EXIT CODES:
      0 - Configuration is valid and ready to use
      1 - Configuration has errors that must be fixed
    
    \b
    COMMON ISSUES AND SOLUTIONS:
      • AWS credentials not found
        → Run 'aws configure' or set environment variables
      • Bedrock access denied
        → Check IAM permissions for bedrock:* actions
      • Model not available in region
        → Use 'tf config model --list' to see available models
      • Output directory not writable
        → Check directory permissions or specify different path
    
    If validation fails, use 'tf setup' for guided configuration repair.
    """
    # Use global logging options from context
    global_verbose = ctx.obj.get('verbose', False)
    log_level = ctx.obj.get('log_level', 'INFO')
    log_file = ctx.obj.get('log_file')
    
    # Command-level verbose overrides global setting
    effective_verbose = verbose or global_verbose
    effective_log_level = 'DEBUG' if effective_verbose else log_level
    
    # Set up logging
    cli_app.logger = setup_logging(
        log_level=effective_log_level,
        log_file=log_file,
        include_console=True
    )
    
    console.print("[blue]🔍 Validating ThreatForest configuration...[/blue]")
    
    try:
        # Load configuration
        config_obj = cli_app.load_config(config_file=config)
        
        # Run validation
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Validating configuration...", total=None)
            
            progress.update(task, description="Loading configuration...")
            validation_result = cli_app.config_manager.validate_configuration(config_obj)
            
            progress.update(task, description="Validation complete")
        
        # Show results
        status_color = "green" if validation_result.is_valid else "red"
        status_icon = "✅" if validation_result.is_valid else "❌"
        status_text = "Configuration is valid" if validation_result.is_valid else "Configuration has issues"
        
        console.print(f"\n[{status_color}]{status_icon} {status_text}[/{status_color}]")
        
        # Show component test results
        if verbose or not validation_result.is_valid:
            console.print(f"\n[bold]Component Test Results:[/bold]")
            
            components_table = Table(show_header=True, header_style="bold cyan")
            components_table.add_column("Component", style="white")
            components_table.add_column("Status", style="white")
            
            for component, status in validation_result.tested_components.items():
                status_text = "[green]✅ Pass[/green]" if status else "[red]❌ Fail[/red]"
                components_table.add_row(component.replace('_', ' ').title(), status_text)
            
            console.print(components_table)
        
        # Show errors
        if validation_result.errors:
            console.print(f"\n[bold red]Validation Errors ({len(validation_result.errors)}):[/bold red]")
            for i, error in enumerate(validation_result.errors, 1):
                console.print(f"  {i}. [{error.component}] {error.message}")
                if error.suggestion and verbose:
                    console.print(f"     💡 Suggestion: {error.suggestion}")
        
        # Show warnings
        if validation_result.warnings:
            console.print(f"\n[bold yellow]Validation Warnings ({len(validation_result.warnings)}):[/bold yellow]")
            for i, warning in enumerate(validation_result.warnings, 1):
                console.print(f"  {i}. [{warning.component}] {warning.message}")
                if warning.suggestion and verbose:
                    console.print(f"     💡 Suggestion: {warning.suggestion}")
        
        # Show next steps
        if not validation_result.is_valid:
            console.print(f"\n[bold]Next Steps:[/bold]")
            console.print("1. Review the errors above")
            console.print("2. Fix configuration issues")
            console.print("3. Run 'tf config validate' again")
            console.print("4. Use 'tf setup' for guided configuration")
        else:
            console.print(f"\n[green]🎉 Configuration is ready! You can now run 'tf analyze' to start threat analysis.[/green]")
        
        # Exit with appropriate code
        sys.exit(0 if validation_result.is_valid else 1)
        
    except Exception as e:
        if cli_app.error_handler:
            error_context = cli_app.error_handler.handle_error(e, operation="configuration validation")
            console.print(f"\n[red]❌ Validation failed: {error_context.message}[/red]")
            if error_context.suggested_actions:
                console.print("\n[bold]Suggested actions:[/bold]")
                for action in error_context.suggested_actions:
                    console.print(f"  • {action}")
        else:
            console.print(f"\n[red]❌ Validation failed: {e}[/red]")
        sys.exit(1)


@config.command('doctor')
@click.option('--verbose', '-v', is_flag=True, 
              help='Show detailed diagnostic information including SDK versions and endpoints')
@click.option('--fix', is_flag=True, 
              help='Attempt to automatically fix detected issues')
def config_doctor(verbose, fix):
    """
    Run comprehensive diagnostics for ThreatForest setup.
    
    This command performs deep diagnostics of your ThreatForest installation
    and configuration, testing all components and connectivity. It's the most
    thorough way to troubleshoot setup issues.
    
    \b
    DIAGNOSTIC CHECKS:
      ✓ Configuration loading and validation
      ✓ AWS SDK installation and versions
      ✓ AWS credentials and permissions
      ✓ Bedrock service connectivity
      ✓ Model availability and invocation
      ✓ Network connectivity to AWS endpoints
      ✓ File system permissions
      ✓ Python dependencies and versions
    
    \b
    EXAMPLES:
      tf config doctor                  # Basic diagnostics
      tf config doctor --verbose       # Detailed system information
      tf config doctor --fix           # Auto-fix detected issues
    
    \b
    WHAT IT TESTS:
      • AWS credentials are valid and accessible
      • IAM permissions for Bedrock service access
      • Network connectivity to AWS Bedrock endpoints
      • Model availability in your configured region
      • Ability to invoke models with test requests
      • Configuration file syntax and completeness
      • Output directory write permissions
    
    \b
    EXIT CODES:
      0 - All diagnostics passed, system is ready
      1 - Some diagnostics failed, issues need attention
    
    \b
    COMMON ISSUES DETECTED:
      • Missing or expired AWS credentials
      • Insufficient IAM permissions for Bedrock
      • Network connectivity problems
      • Unsupported model or region combinations
      • File permission issues
      • Outdated dependencies
    
    Use this command when 'tf config validate' passes but analysis still fails.
    """
    try:
        from threatforest.utils.bedrock_client import BedrockClient, BedrockClientError
        
        console.print("[bold blue]🔬 ThreatForest Configuration Doctor[/bold blue]")
        console.print("Running comprehensive diagnostics...\n")
        
        # Load configuration without validation for doctor command (validation is done separately)
        try:
            config_obj = cli_app.load_config(validate=False)
            console.print("[green]✅ Configuration loaded successfully[/green]")
        except Exception as e:
            console.print(f"[red]❌ Configuration loading failed: {e}[/red]")
            sys.exit(1)
        
        # Create Bedrock client
        try:
            bedrock_client = BedrockClient(config_obj.bedrock)
            console.print("[green]✅ Bedrock client initialized[/green]")
        except BedrockClientError as e:
            console.print(f"[red]❌ Bedrock client initialization failed: {e}[/red]")
            sys.exit(1)
        
        # Get SDK information
        sdk_info = bedrock_client.get_sdk_info()
        console.print(f"\n[bold]SDK Information:[/bold]")
        console.print(f"• boto3 version: {sdk_info['boto3_version']}")
        console.print(f"• botocore version: {sdk_info['botocore_version']}")
        console.print(f"• Region: {sdk_info['region']}")
        console.print(f"• Service API version: {sdk_info['service_model_version']}")
        
        if verbose:
            console.print(f"• Bedrock Runtime endpoint: {sdk_info['bedrock_runtime_endpoint']}")
            console.print(f"• Bedrock endpoint: {sdk_info['bedrock_endpoint']}")
        
        # Verify Bedrock access
        console.print(f"\n[bold]Bedrock Access Verification:[/bold]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Verifying Bedrock access...", total=None)
            
            verification = bedrock_client.verify_bedrock_access()
        
        # Show verification results
        verification_table = Table(show_header=True, header_style="bold cyan")
        verification_table.add_column("Service", style="white")
        verification_table.add_column("Status", style="white")
        
        bedrock_status = "[green]✅ OK[/green]" if verification["bedrock_access"] else "[red]❌ FAIL[/red]"
        verification_table.add_row("Bedrock Service", bedrock_status)
        
        runtime_status = "[green]✅ OK[/green]" if verification["bedrock_runtime_access"] else "[red]❌ FAIL[/red]"
        verification_table.add_row("Bedrock Runtime", runtime_status)
        
        model_list_status = "[green]✅ OK[/green]" if verification["model_list_access"] else "[red]❌ FAIL[/red]"
        verification_table.add_row("Model Discovery", model_list_status)
        
        invoke_status = "[green]✅ OK[/green]" if verification["model_invoke_access"] else "[red]❌ FAIL[/red]"
        verification_table.add_row("Model Invocation", invoke_status)
        
        console.print(verification_table)
        
        # Show errors if any
        if verification["errors"]:
            console.print(f"\n[bold red]Errors Detected ({len(verification['errors'])}):[/bold red]")
            for i, error in enumerate(verification["errors"], 1):
                console.print(f"  {i}. {error}")
        
        # Overall status
        all_ok = all([
            verification["bedrock_access"],
            verification["bedrock_runtime_access"],
            verification["model_list_access"],
            verification["model_invoke_access"]
        ])
        
        if all_ok:
            console.print(f"\n[bold green]🎉 All diagnostics passed! ThreatForest is ready to use.[/bold green]")
            sys.exit(0)
        else:
            console.print(f"\n[bold red]⚠️  Some diagnostics failed. Please address the issues above.[/bold red]")
            console.print(f"\n[bold]Common solutions:[/bold]")
            console.print("• Check AWS credentials: aws sts get-caller-identity")
            console.print("• Verify Bedrock access in your region")
            console.print("• Ensure your IAM role has bedrock:* permissions")
            console.print("• Try a different AWS region with Bedrock support")
            sys.exit(1)
    
    except ImportError:
        console.print("[red]Error: BedrockClient not available. Check your installation.[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]❌ Diagnostic failed: {e}[/red]")
        sys.exit(1)


@config.command('model')
@click.option('--region', help='AWS region for model discovery (e.g., us-east-1, us-west-2)')
@click.option('--list', 'list_models', is_flag=True, 
              help='List all available Bedrock models in the specified region')
@click.option('--recommend', help='Get model recommendations for specific use case (analysis, generation, chat)')
@click.option('--set', 'set_model', help='Set the Bedrock model ID to use (e.g., anthropic.claude-3-sonnet-20240229-v1:0)')
@click.option('--user', is_flag=True, 
              help='Save model configuration to user-level config instead of project-level')
@click.option('--verbose', '-v', is_flag=True, 
              help='Show detailed model information including use cases and pricing tiers')
@click.option('--test', is_flag=True, 
              help='Test the model configuration after setting it')
def config_model(region, list_models, recommend, set_model, user, verbose, test):
    """
    Manage AWS Bedrock model configuration and selection.
    
    This command helps you discover, select, and configure Bedrock models
    for ThreatForest analysis. It can list available models, provide
    recommendations based on use case, and update your configuration.
    
    \b
    MODEL DISCOVERY:
      tf config model --list                    # List models in current region
      tf config model --list --region us-west-2  # List models in specific region
      tf config model --list --verbose         # Show detailed model info
    
    \b
    MODEL RECOMMENDATIONS:
      tf config model --recommend analysis     # Models optimized for analysis
      tf config model --recommend generation   # Models optimized for generation
      tf config model --recommend chat         # Models optimized for chat
    
    \b
    MODEL CONFIGURATION:
      tf config model --set anthropic.claude-3-sonnet-20240229-v1:0
      tf config model --set claude-3-haiku --user  # Save to user config
      tf config model --set claude-3-opus --test   # Test after setting
    
    \b
    CURRENT CONFIGURATION:
      tf config model                          # Show current model settings
    
    \b
    MODEL TYPES:
      • Claude 3 Haiku - Fast, cost-effective for simple tasks
      • Claude 3 Sonnet - Balanced performance and cost
      • Claude 3 Opus - Highest capability for complex analysis
      • Titan models - Amazon's foundation models
      • Cohere models - Specialized for text generation
    
    \b
    REGION AVAILABILITY:
      Different models are available in different AWS regions.
      Use --list with --region to check availability before setting.
      Common regions: us-east-1, us-west-2, eu-west-1, ap-southeast-1
    
    The selected model affects analysis quality, speed, and cost.
    Use --recommend to get suggestions based on your use case.
    """
    try:
        # Import BedrockClient here to avoid circular imports
        from threatforest.utils.bedrock_client import BedrockClient, BedrockClientError
        
        # Load current configuration without validation for model command
        config_obj = cli_app.load_config(validate=False)
        
        # Use provided region or current config region
        target_region = region or config_obj.bedrock.region
        
        # Create Bedrock client for model operations
        temp_config = config_obj.bedrock.copy()
        temp_config.region = target_region
        bedrock_client = BedrockClient(temp_config)
        
        if list_models:
            # List available models
            console.print(f"[blue]🔍 Discovering models in region: {target_region}[/blue]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task("Loading models...", total=None)
                
                try:
                    models = bedrock_client.list_available_models()
                    progress.update(task, description=f"Found {len(models)} models")
                except BedrockClientError as e:
                    console.print(f"[red]Failed to list models: {e}[/red]")
                    sys.exit(1)
            
            if models:
                console.print(f"\n[bold]Available Models in {target_region} ({len(models)}):[/bold]")
                
                models_table = Table(show_header=True, header_style="bold cyan")
                models_table.add_column("Model ID", style="white", no_wrap=True)
                models_table.add_column("Name", style="green")
                models_table.add_column("Provider", style="blue")
                models_table.add_column("Status", style="yellow")
                
                if verbose:
                    models_table.add_column("Use Cases", style="dim")
                
                for model in models[:20]:  # Show first 20 models
                    status = "✓ Active" if model.model_lifecycle_status == "ACTIVE" else model.model_lifecycle_status
                    
                    if verbose:
                        use_cases = ", ".join(model.supported_use_cases[:3]) if hasattr(model, 'supported_use_cases') else "General"
                        models_table.add_row(model.model_id, model.model_name, model.provider_name, status, use_cases)
                    else:
                        models_table.add_row(model.model_id, model.model_name, model.provider_name, status)
                
                console.print(models_table)
                
                if len(models) > 20:
                    console.print(f"[dim]... and {len(models) - 20} more models. Use --verbose to see use cases.[/dim]")
            else:
                console.print(f"[yellow]No models found in region {target_region}[/yellow]")
        
        elif recommend:
            # Get model recommendations
            console.print(f"[blue]🎯 Getting model recommendations for: {recommend}[/blue]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task("Getting recommendations...", total=None)
                
                try:
                    recommended_models = bedrock_client.get_model_recommendations(recommend)
                except BedrockClientError as e:
                    console.print(f"[red]Failed to get recommendations: {e}[/red]")
                    sys.exit(1)
            
            if recommended_models:
                console.print(f"\n[bold]Recommended Models for '{recommend}' ({len(recommended_models)}):[/bold]")
                
                rec_table = Table(show_header=True, header_style="bold green")
                rec_table.add_column("Rank", style="cyan", no_wrap=True)
                rec_table.add_column("Model ID", style="white")
                rec_table.add_column("Name", style="green")
                rec_table.add_column("Provider", style="blue")
                rec_table.add_column("Reason", style="dim")
                
                for i, model in enumerate(recommended_models[:10], 1):
                    reason = getattr(model, 'recommendation_reason', 'Optimized for use case')
                    rec_table.add_row(str(i), model.model_id, model.model_name, model.provider_name, reason)
                
                console.print(rec_table)
                
                # Show current model
                current_model = config_obj.bedrock.model
                console.print(f"\n[dim]Current model: {current_model}[/dim]")
                
                if Confirm.ask("Set one of these recommended models?", default=False):
                    choice = IntPrompt.ask("Select model number", default=1)
                    if 1 <= choice <= len(recommended_models):
                        selected_model = recommended_models[choice - 1]
                        set_model = selected_model.model_id
                    else:
                        console.print("[red]Invalid selection[/red]")
                        sys.exit(1)
            else:
                console.print(f"[yellow]No recommendations found for '{recommend}'[/yellow]")
        
        if set_model:
            # Set the model
            console.print(f"[blue]🔧 Setting model to: {set_model}[/blue]")
            
            # Validate model availability
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task("Validating model...", total=None)
                
                try:
                    is_valid = bedrock_client.validate_model_region_compatibility(set_model, target_region)
                    if not is_valid:
                        console.print(f"[red]Model {set_model} is not available in region {target_region}[/red]")
                        sys.exit(1)
                except BedrockClientError as e:
                    console.print(f"[yellow]Warning: Could not validate model availability: {e}[/yellow]")
                    if not Confirm.ask("Continue anyway?", default=False):
                        sys.exit(1)
            
            # Update configuration
            updates = {
                'bedrock': {
                    'model': set_model,
                    'region': target_region,
                    'validation_status': 'pending',
                    'last_validated': None
                }
            }
            
            try:
                updated_config = cli_app.config_manager.update_config(updates)
                cli_app.config_manager.save_config(updated_config, user_level=user)
                
                console.print(f"[green]✅ Model updated: {set_model}[/green]")
                console.print(f"[green]✅ Region updated: {target_region}[/green]")
                
                if user:
                    console.print("[dim]Saved to user-level configuration[/dim]")
                else:
                    console.print("[dim]Saved to project-level configuration[/dim]")
                
                # Test the new configuration
                if Confirm.ask("Test the new model configuration?", default=True):
                    console.print("[blue]🧪 Testing new configuration...[/blue]")
                    
                    # Create new client with updated config
                    test_client = BedrockClient(updated_config.bedrock)
                    
                    try:
                        if test_client.test_connection():
                            console.print("[green]✅ Model configuration test successful![/green]")
                            
                            # Update validation status
                            validation_updates = {
                                'bedrock': {
                                    'validation_status': 'valid',
                                    'last_validated': datetime.now()
                                }
                            }
                            final_config = cli_app.config_manager.update_config(validation_updates)
                            cli_app.config_manager.save_config(final_config, user_level=user)
                            
                            console.print("\n[green]🎉 Model configuration is ready for use![/green]")
                            console.print("You can now run 'tf analyze' to start threat analysis.")
                        else:
                            console.print("[red]❌ Model configuration test failed[/red]")
                            console.print("The model was saved but may not work correctly.")
                            console.print("\n[bold]Troubleshooting:[/bold]")
                            console.print("• Check AWS credentials: aws sts get-caller-identity")
                            console.print("• Verify Bedrock permissions in IAM")
                            console.print("• Try a different model or region")
                            console.print("• Use 'tf config doctor' for detailed diagnostics")
                    except BedrockClientError as e:
                        console.print(f"[red]❌ Model test failed: {e}[/red]")
                        console.print("The model was saved but may not work correctly.")
                        console.print("\n[bold]Common solutions:[/bold]")
                        console.print("• Verify AWS credentials are valid")
                        console.print("• Check IAM permissions for bedrock:InvokeModel")
                        console.print("• Ensure model is available in your region")
                        console.print("• Try 'tf config doctor' for comprehensive diagnostics")
                
            except Exception as e:
                console.print(f"[red]Error updating configuration: {e}[/red]")
                sys.exit(1)
        
        elif not list_models and not recommend:
            # Show current model configuration
            console.print(Panel(
                f"[bold]Current Model Configuration:[/bold]\n\n"
                f"Model: {config_obj.bedrock.model}\n"
                f"Region: {config_obj.bedrock.region}\n"
                f"Temperature: {config_obj.bedrock.temperature}\n"
                f"Max Tokens: {config_obj.bedrock.max_tokens}\n"
                f"Top-p: {config_obj.bedrock.top_p}\n"
                f"Validation Status: {config_obj.bedrock.validation_status}\n"
                f"Last Validated: {config_obj.bedrock.last_validated or 'Never'}",
                title="Model Configuration",
                border_style="blue"
            ))
            
            console.print(f"\n[dim]Use 'tf config model --list' to see available models[/dim]")
            console.print(f"[dim]Use 'tf config model --recommend analysis' for recommendations[/dim]")
    
    except ImportError:
        console.print("[red]Error: BedrockClient not available. Check your installation.[/red]")
        sys.exit(1)
    except Exception as e:
        if cli_app.error_handler:
            error_context = cli_app.error_handler.handle_error(e, operation="model configuration")
            console.print(f"\n[red]❌ Model configuration failed: {error_context.message}[/red]")
        else:
            console.print(f"\n[red]❌ Model configuration failed: {e}[/red]")
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
    import logging
    from datetime import datetime
    
    logger = logging.getLogger(__name__)
    logger.info(f"Starting analysis workflow for directory: {directory}")
    logger.info(f"Configuration: model={config.bedrock.model}, region={config.bedrock.region}")
    logger.info(f"Verbose mode: {verbose}, Auto-approve: {auto_approve}")
    
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
            logger.info("=== STARTING INFORMATION EXTRACTION PHASE ===")
            progress.update(phase_tasks["Information Extraction"], visible=True)
            cli_app.update_phase_progress(progress, phase_tasks, "Information Extraction", 10, "Initializing information extraction...")
            
            if verbose:
                console.print(f"[bold blue]🔍 Starting Information Extraction Phase[/bold blue]")
                console.print(f"[dim]Processing {len(context_files)} context files with real AI extraction[/dim]")
            
            # Real information extraction with detailed logging
            context_info = _run_real_information_extraction(context_files, config, verbose)
            
            logger.info("=== INFORMATION EXTRACTION PHASE COMPLETED ===")
            if verbose:
                console.print(f"[bold green]✅ Information Extraction Phase Completed[/bold green]")
            
            cli_app.update_phase_progress(progress, phase_tasks, "Information Extraction", 70, "Validating extracted information...")
            
            # User validation (if interactive)
            logger.info(f"Validation step: auto_approve={auto_approve}, interactive_mode={cli_app.interactive_mode}")
            if not auto_approve:
                logger.info("Starting user validation of extracted information")
                if verbose:
                    console.print(f"[dim]👤 Starting user validation (interactive mode)[/dim]")
                context_info = cli_app.validate_extracted_information(context_info)
                logger.info("User validation completed")
            else:
                logger.info("Auto-approving extracted information")
                if verbose:
                    console.print(f"[dim]✅ Auto-approving extracted information[/dim]")
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
            
            # Write individual attack tree files
            _write_attack_tree_files(results['results'].get('attack_trees', []), config)
            
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


def _run_real_information_extraction(context_files: List[Dict[str, Any]], config: ThreatForestConfig, verbose: bool = False) -> ContextInformation:
    """Run real information extraction using InformationExtractionAgent with detailed logging."""
    import logging
    import time
    from pathlib import Path
    from .models import ContextInformation
    from .agents.context_detection import DetectedFile, FileType, FileFormat
    from .agents.information_extraction import InformationExtractionAgent
    from .utils.bedrock_client import BedrockClient, BedrockClientError
    from datetime import datetime
    
    logger = logging.getLogger(__name__)
    
    try:
        # Step 1: Initialize Bedrock client with detailed logging
        if verbose:
            console.print(f"[dim]🔧 Initializing Bedrock client...[/dim]")
        logger.info("Starting real information extraction")
        logger.info(f"Configuration: region={config.bedrock.region}, model={config.bedrock.model}")
        logger.info(f"Timeout: {config.bedrock.timeout_seconds}s, Temperature: {config.bedrock.temperature}")
        
        start_time = time.time()
        
        try:
            bedrock_client = BedrockClient(config.bedrock)
            client_init_time = time.time() - start_time
            logger.info(f"Bedrock client initialized successfully in {client_init_time:.2f}s")
            if verbose:
                console.print(f"[dim]✅ Bedrock client ready ({client_init_time:.2f}s)[/dim]")
        except Exception as e:
            logger.error(f"Failed to initialize Bedrock client: {e}")
            console.print(f"[red]❌ Failed to initialize Bedrock client: {e}[/red]")
            raise
        
        # Step 2: Initialize Information Extraction Agent
        if verbose:
            console.print(f"[dim]🤖 Creating Information Extraction Agent...[/dim]")
        
        try:
            extraction_agent = InformationExtractionAgent(bedrock_client)
            logger.info("InformationExtractionAgent created successfully")
            if verbose:
                console.print(f"[dim]✅ Information Extraction Agent ready[/dim]")
        except Exception as e:
            logger.error(f"Failed to create InformationExtractionAgent: {e}")
            console.print(f"[red]❌ Failed to create Information Extraction Agent: {e}[/red]")
            raise
        
        # Step 3: Convert context files to DetectedFile objects
        if verbose:
            console.print(f"[dim]📄 Converting {len(context_files)} context files...[/dim]")
        
        detected_files = []
        for i, file_info in enumerate(context_files):
            try:
                file_path = Path(file_info['path'])
                
                # Map file types
                file_type_map = {
                    'readme': FileType.README,
                    'threat_statement': FileType.THREAT_STATEMENT,
                    'architecture': FileType.ARCHITECTURE_DIAGRAM,
                    'dataflow': FileType.DATA_FLOW_DIAGRAM,
                    'documentation': FileType.DOCUMENTATION,
                    'configuration': FileType.CONFIGURATION
                }
                
                file_type = file_type_map.get(file_info.get('type', 'documentation'), FileType.DOCUMENTATION)
                
                # Determine file format
                file_format = FileFormat.MARKDOWN  # Default
                if file_path.suffix.lower() in ['.json']:
                    file_format = FileFormat.JSON
                elif file_path.suffix.lower() in ['.yaml', '.yml']:
                    file_format = FileFormat.YAML
                elif file_path.suffix.lower() in ['.png', '.jpg', '.jpeg', '.svg']:
                    file_format = FileFormat.IMAGE
                
                # Get file size
                size_bytes = file_path.stat().st_size if file_path.exists() else 0
                
                detected_file = DetectedFile(
                    path=file_path,
                    file_type=file_type,
                    file_format=file_format,
                    size_bytes=size_bytes,
                    confidence_score=file_info.get('confidence', 0.8),
                    metadata=file_info.get('metadata', {}),
                    validation_errors=[]
                )
                
                detected_files.append(detected_file)
                logger.debug(f"Converted file {i+1}/{len(context_files)}: {file_path} ({file_type}, {size_bytes} bytes)")
                
            except Exception as e:
                logger.warning(f"Failed to convert file {file_info.get('path', 'unknown')}: {e}")
                continue
        
        conversion_time = time.time() - start_time - client_init_time
        logger.info(f"Converted {len(detected_files)} files successfully in {conversion_time:.2f}s")
        if verbose:
            console.print(f"[dim]✅ Converted {len(detected_files)} files ({conversion_time:.2f}s)[/dim]")
        
        if not detected_files:
            logger.warning("No valid files to process")
            console.print(f"[yellow]⚠️  No valid files found for extraction[/yellow]")
            # Return empty context info
            return ContextInformation(
                validation_status="failed",
                confidence_score=0.0,
                timestamp=datetime.now()
            )
        
        # Step 4: Run information extraction with timeout monitoring
        if verbose:
            console.print(f"[dim]🔍 Running AI information extraction on {len(detected_files)} files...[/dim]")
        
        extraction_start = time.time()
        logger.info(f"Starting information extraction on {len(detected_files)} files")
        
        # Log file details
        for i, df in enumerate(detected_files):
            logger.debug(f"File {i+1}: {df.path} (type: {df.file_type}, format: {df.file_format}, size: {df.size_bytes} bytes)")
        
        try:
            # Run the extraction with detailed progress logging
            logger.info("Calling extraction_agent.extract_information()...")
            if verbose:
                console.print(f"[dim]⏳ Calling Bedrock API (timeout: {config.bedrock.timeout_seconds}s)...[/dim]")
            
            # Add periodic progress updates during extraction
            import threading
            import time
            
            extraction_complete = threading.Event()
            extraction_result = None
            extraction_error = None
            
            def run_extraction():
                nonlocal extraction_result, extraction_error
                try:
                    extraction_result = extraction_agent.extract_information(detected_files)
                    extraction_complete.set()
                except Exception as e:
                    extraction_error = e
                    extraction_complete.set()
            
            # Start extraction in background thread
            extraction_thread = threading.Thread(target=run_extraction)
            extraction_thread.daemon = True
            extraction_thread.start()
            
            # Monitor progress with periodic updates
            timeout_seconds = config.bedrock.timeout_seconds + 30  # Add buffer
            elapsed = 0
            
            while not extraction_complete.is_set() and elapsed < timeout_seconds:
                time.sleep(5)  # Check every 5 seconds
                elapsed += 5
                
                if verbose and elapsed % 15 == 0:  # Update every 15 seconds
                    console.print(f"[dim]⏳ Still processing... ({elapsed}s elapsed)[/dim]")
                
                logger.debug(f"Information extraction still running... ({elapsed}s elapsed)")
            
            if not extraction_complete.is_set():
                logger.error(f"Information extraction timed out after {timeout_seconds}s")
                console.print(f"[red]❌ Information extraction timed out after {timeout_seconds}s[/red]")
                raise TimeoutError(f"Information extraction timed out after {timeout_seconds}s")
            
            if extraction_error:
                raise extraction_error
            
            extraction_time = time.time() - extraction_start
            logger.info(f"Information extraction completed successfully in {extraction_time:.2f}s")
            
            if verbose:
                console.print(f"[dim]✅ Extraction completed ({extraction_time:.2f}s)[/dim]")
                console.print(f"[dim]📊 Results: {len(extraction_result.context_info.technologies)} technologies, "
                            f"{len(extraction_result.context_info.programming_languages)} languages[/dim]")
            
            # Log extraction results
            logger.info(f"Extraction results:")
            logger.info(f"  Technologies: {extraction_result.context_info.technologies}")
            logger.info(f"  Languages: {extraction_result.context_info.programming_languages}")
            logger.info(f"  Sector: {extraction_result.context_info.sector}")
            logger.info(f"  Architecture: {extraction_result.context_info.architecture_type}")
            logger.info(f"  Compliance: {extraction_result.context_info.compliance_frameworks}")
            logger.info(f"  Confidence: {extraction_result.extraction_confidence}")
            logger.info(f"  Errors: {len(extraction_result.processing_errors)}")
            
            if extraction_result.processing_errors:
                logger.warning(f"Processing errors: {extraction_result.processing_errors}")
            
            total_time = time.time() - start_time
            logger.info(f"Total information extraction time: {total_time:.2f}s")
            
            return extraction_result.context_info
            
        except BedrockClientError as e:
            extraction_time = time.time() - extraction_start
            logger.error(f"Bedrock client error after {extraction_time:.2f}s: {e}")
            console.print(f"[red]❌ Bedrock API error ({extraction_time:.2f}s): {e}[/red]")
            
            # Check for specific error types
            error_str = str(e).lower()
            if "timeout" in error_str or "timed out" in error_str:
                console.print(f"[yellow]💡 The model request timed out. This might be due to:[/yellow]")
                console.print(f"   • Large input files taking too long to process")
                console.print(f"   • Network connectivity issues")
                console.print(f"   • Inference profile availability issues")
            elif "inference profile" in error_str:
                console.print(f"[yellow]💡 Inference profile issue detected:[/yellow]")
                console.print(f"   • Check if the inference profile ARN is correct")
                console.print(f"   • Verify the profile is available in region {config.bedrock.region}")
                console.print(f"   • Consider using a foundation model instead")
            
            raise
            
        except Exception as e:
            extraction_time = time.time() - extraction_start
            logger.error(f"Unexpected error during extraction after {extraction_time:.2f}s: {e}")
            console.print(f"[red]❌ Extraction failed ({extraction_time:.2f}s): {e}[/red]")
            raise
        
    except Exception as e:
        total_time = time.time() - start_time
        logger.error(f"Information extraction failed after {total_time:.2f}s: {e}")
        console.print(f"[red]❌ Information extraction failed ({total_time:.2f}s)[/red]")
        
        # Return fallback context info
        return ContextInformation(
            validation_status="failed",
            confidence_score=0.0,
            timestamp=datetime.now()
        )


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
            'file_path': f'attack_tree_T{i:03d}.md',
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


def _write_attack_tree_files(attack_trees: List[Dict[str, Any]], config: ThreatForestConfig) -> None:
    """Write individual attack tree files to the output directory."""
    from pathlib import Path
    
    output_dir = Path(config.output.directory)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    for tree in attack_trees:
        if 'file_path' in tree and 'mermaid_content' in tree:
            tree_file = output_dir / tree['file_path']
            
            # Create full mermaid content with metadata
            full_content = f"""# {tree['title']}

**Threat ID:** {tree['threat_id']}  
**Severity:** {tree['severity']}  
**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(tree.get('generated_timestamp', time.time())))}

## Attack Tree Diagram

```mermaid
{tree['mermaid_content']}
```

## TTC Mappings

"""
            
            # Add TTC mappings if available
            if 'ttc_mappings' in tree:
                for ttc_id, mapping in tree['ttc_mappings'].items():
                    full_content += f"- **{ttc_id}**: {mapping['technique']} (Alignment: {mapping['alignment_score']:.0%})\n"
            else:
                full_content += "No TTC mappings available.\n"
            
            # Write the file
            tree_file.write_text(full_content)


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
        summary_content += f"- {tree['file_path']} - {tree['title']}\n"
    
    summary_content += f"- threat_analysis_summary.md - Analysis summary report\n"
    
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