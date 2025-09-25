"""
Interactive setup wizard for ThreatForest configuration.

This module provides a step-by-step interactive setup process to help users
configure their ThreatForest installation with appropriate model providers,
credentials, and preferences.
"""

import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt, FloatPrompt
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

from .config import ConfigManager, ThreatForestConfig, BedrockConfig, ValidationResult
# Lazy imports to avoid circular dependencies
BedrockClient = None
ModelInfo = None
BedrockClientError = None

def _import_bedrock_classes():
    """Lazy import of Bedrock classes to avoid circular dependencies."""
    global BedrockClient, ModelInfo, BedrockClientError
    if BedrockClient is None:
        from threatforest.utils.bedrock_client import BedrockClient as _BedrockClient
        from threatforest.utils.bedrock_client import ModelInfo as _ModelInfo
        from threatforest.utils.bedrock_client import BedrockClientError as _BedrockClientError
        BedrockClient = _BedrockClient
        ModelInfo = _ModelInfo
        BedrockClientError = _BedrockClientError


logger = logging.getLogger(__name__)
console = Console()


class SetupWizardError(Exception):
    """Custom exception for setup wizard errors."""
    pass


class SetupWizard:
    """
    Interactive setup wizard for ThreatForest configuration.
    
    Guides users through the process of configuring their ThreatForest installation
    with appropriate model providers, credentials, and preferences.
    """
    
    def __init__(self, project_dir: Optional[str] = None):
        """
        Initialize the setup wizard.
        
        Args:
            project_dir: Project directory for configuration (defaults to current directory)
        """
        self.project_dir = Path(project_dir) if project_dir else Path.cwd()
        self.config_manager = ConfigManager(str(self.project_dir))
        self.logger = logging.getLogger(__name__)
        
        # Setup wizard state
        self._aws_credentials_valid = False
        self._available_models: List[Any] = []  # List[ModelInfo] after lazy import
        self._selected_config: Optional[ThreatForestConfig] = None
    
    def run_interactive_setup(self) -> ThreatForestConfig:
        """
        Run the complete interactive setup wizard.
        
        Returns:
            Configured ThreatForestConfig instance
            
        Raises:
            SetupWizardError: If setup fails or is cancelled
        """
        self.logger.info("Starting interactive setup wizard")
        
        try:
            # Show welcome screen
            self._show_welcome_screen()
            
            # Step 1: Detect and validate AWS credentials
            self.logger.info("Step 1: AWS credential detection and validation")
            credential_status = self.detect_aws_credentials()
            
            if not credential_status.is_valid:
                if not self._handle_credential_setup():
                    raise SetupWizardError("AWS credentials setup cancelled or failed")
            
            # Step 2: Configure Bedrock settings
            self.logger.info("Step 2: Bedrock configuration")
            bedrock_config = self.configure_bedrock_settings()
            
            # Step 3: Configure other settings
            self.logger.info("Step 3: Additional configuration")
            additional_config = self._configure_additional_settings()
            
            # Step 4: Create complete configuration
            self.logger.info("Step 4: Creating complete configuration")
            config_data = {
                'bedrock': bedrock_config,
                **additional_config
            }
            
            config = ThreatForestConfig(**config_data)
            
            # Step 5: Test configuration
            self.logger.info("Step 5: Testing configuration")
            validation_result = self.test_configuration(config)
            
            if not validation_result.is_valid:
                if not self._handle_validation_errors(validation_result):
                    raise SetupWizardError("Configuration validation failed")
            
            # Step 6: Save configuration
            self.logger.info("Step 6: Saving configuration")
            scope = self._prompt_for_configuration_scope()
            self.save_configuration(config, scope)
            
            self._selected_config = config
            self._show_completion_screen(config, scope)
            
            self.logger.info("Interactive setup wizard completed successfully")
            return config
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Setup cancelled by user[/yellow]")
            self.logger.info("Setup wizard cancelled by user")
            raise SetupWizardError("Setup cancelled by user")
        
        except Exception as e:
            self.logger.error(f"Setup wizard failed: {e}")
            console.print(f"\n[red]Setup failed: {e}[/red]")
            raise SetupWizardError(f"Setup failed: {e}")
    
    def detect_aws_credentials(self) -> 'CredentialStatus':
        """
        Detect and validate AWS credentials using boto3 session checks.
        
        Returns:
            CredentialStatus object with validation results
        """
        self.logger.info("Detecting AWS credentials")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Checking AWS credentials...", total=None)
            
            try:
                # Create boto3 session to test credentials
                session = boto3.Session()
                credentials = session.get_credentials()
                
                if credentials is None:
                    self.logger.warning("No AWS credentials found")
                    return CredentialStatus(
                        is_valid=False,
                        error_type="no_credentials",
                        message="No AWS credentials found",
                        suggestion="Configure AWS credentials using 'aws configure', environment variables, or IAM roles",
                        detection_method="boto3_session"
                    )
                
                # Test credentials with STS call
                progress.update(task, description="Validating credentials with AWS...")
                sts_client = session.client('sts')
                identity = sts_client.get_caller_identity()
                
                self.logger.info(f"AWS credentials validated for account: {identity.get('Account', 'unknown')}")
                self._aws_credentials_valid = True
                
                return CredentialStatus(
                    is_valid=True,
                    account_id=identity.get('Account'),
                    user_arn=identity.get('Arn'),
                    user_id=identity.get('UserId'),
                    detection_method=self._get_credential_source()
                )
                
            except NoCredentialsError:
                self.logger.warning("No AWS credentials configured")
                return CredentialStatus(
                    is_valid=False,
                    error_type="no_credentials",
                    message="No AWS credentials configured",
                    suggestion="Configure AWS credentials using 'aws configure' or environment variables",
                    detection_method="boto3_session"
                )
            
            except PartialCredentialsError as e:
                self.logger.warning(f"Partial AWS credentials: {e}")
                return CredentialStatus(
                    is_valid=False,
                    error_type="partial_credentials",
                    message=f"Partial AWS credentials: {e}",
                    suggestion="Ensure all required credential components are provided",
                    detection_method="boto3_session"
                )
            
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                error_message = e.response.get('Error', {}).get('Message', str(e))
                
                self.logger.warning(f"AWS credential validation failed: {error_code} - {error_message}")
                
                return CredentialStatus(
                    is_valid=False,
                    error_type="credential_error",
                    message=f"AWS credential validation error: {error_message}",
                    suggestion="Check your AWS credentials and permissions",
                    detection_method="boto3_session"
                )
            
            except Exception as e:
                self.logger.error(f"Unexpected error validating AWS credentials: {e}")
                return CredentialStatus(
                    is_valid=False,
                    error_type="unexpected_error",
                    message=f"Unexpected error: {e}",
                    suggestion="Check your AWS configuration and network connectivity",
                    detection_method="boto3_session"
                )
    
    def configure_bedrock_settings(self) -> Dict[str, Any]:
        """
        Configure Bedrock settings through interactive prompts.
        
        Returns:
            Dictionary with Bedrock configuration
        """
        self.logger.info("Starting Bedrock configuration")
        
        console.print(Panel(
            "[bold blue]Bedrock Configuration[/bold blue]\n\n"
            "Let's configure your Amazon Bedrock settings for AI model access.",
            title="Step 2: Bedrock Setup",
            border_style="blue"
        ))
        
        # Select region
        region = self._prompt_for_region()
        self.logger.info(f"Selected region: {region}")
        
        # Discover and select model
        model_id = self._prompt_for_model(region)
        self.logger.info(f"Selected model: {model_id}")
        
        # Configure model parameters
        parameters = self._prompt_for_model_parameters()
        self.logger.info(f"Configured parameters: {parameters}")
        
        bedrock_config = {
            'region': region,
            'model': model_id,
            'timeout_seconds': 300,
            **parameters
        }
        
        self.logger.info("Bedrock configuration completed")
        return bedrock_config
    
    def test_configuration(self, config: ThreatForestConfig) -> ValidationResult:
        """
        Test the configuration by validating connectivity and settings.
        
        Args:
            config: Configuration to test
            
        Returns:
            ValidationResult with test results
        """
        _import_bedrock_classes()  # Lazy import
        
        self.logger.info("Testing configuration")
        
        console.print(Panel(
            "[bold yellow]Testing Configuration[/bold yellow]\n\n"
            "Testing your configuration to ensure everything works correctly...",
            title="Configuration Test",
            border_style="yellow"
        ))
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Testing configuration...", total=None)
            
            # Use ConfigManager's validation method
            progress.update(task, description="Validating configuration...")
            validation_result = self.config_manager.validate_configuration(config)
            
            if validation_result.is_valid:
                progress.update(task, description="Testing Bedrock connectivity...")
                
                # Additional Bedrock connectivity test
                try:
                    bedrock_client = BedrockClient(config.bedrock)
                    connection_test = bedrock_client.test_connection()
                    
                    if not connection_test:
                        validation_result.is_valid = False
                        validation_result.errors.append(
                            type('ValidationError', (), {
                                'component': 'bedrock_connectivity',
                                'error_type': 'connection_failed',
                                'message': 'Bedrock connection test failed',
                                'suggestion': 'Check your model selection and region configuration'
                            })()
                        )
                
                except Exception as e:
                    # Check if it's a BedrockClientError (either real or mock)
                    is_bedrock_error = (
                        (BedrockClientError and isinstance(e, BedrockClientError)) or
                        (hasattr(e, '__class__') and e.__class__.__name__ == "BedrockClientError")
                    )
                    
                    if is_bedrock_error:
                        self.logger.error(f"Bedrock connectivity test failed: {e}")
                        validation_result.is_valid = False
                        validation_result.errors.append(
                            type('ValidationError', (), {
                                'component': 'bedrock_connectivity',
                                'error_type': 'connection_error',
                                'message': f'Bedrock connectivity error: {e}',
                                'suggestion': 'Verify your model and region selection'
                            })()
                        )
                    else:
                        # Re-raise if it's not a BedrockClientError
                        raise
        
        # Show test results
        self._show_test_results(validation_result)
        
        self.logger.info(f"Configuration test completed: valid={validation_result.is_valid}")
        return validation_result
    
    def save_configuration(self, config: ThreatForestConfig, scope: str) -> None:
        """
        Save configuration to the appropriate location.
        
        Args:
            config: Configuration to save
            scope: Configuration scope ('user' or 'project')
        """
        self.logger.info(f"Saving configuration with scope: {scope}")
        
        try:
            user_level = (scope == 'user')
            self.config_manager.save_config(config, user_level=user_level)
            
            config_path = Path.home() / ".tf" / "config.yaml" if user_level else self.project_dir / ".tf" / "config.yaml"
            self.logger.info(f"Configuration saved to: {config_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
            raise SetupWizardError(f"Failed to save configuration: {e}")
    
    def _show_welcome_screen(self) -> None:
        """Show the setup wizard welcome screen."""
        welcome_panel = Panel(
            "[bold green]Welcome to ThreatForest Setup Wizard![/bold green] 🌳\n\n"
            "This wizard will guide you through configuring ThreatForest for your environment.\n\n"
            "[bold]What we'll configure:[/bold]\n"
            "• AWS credentials and permissions\n"
            "• Amazon Bedrock model selection\n"
            "• Model parameters and preferences\n"
            "• Output and processing settings\n\n"
            "[dim]Press Ctrl+C at any time to cancel setup[/dim]",
            title="ThreatForest Setup",
            border_style="green"
        )
        console.print(welcome_panel)
        
        if not Confirm.ask("\nReady to begin setup?", default=True):
            raise SetupWizardError("Setup cancelled by user")
    
    def _handle_credential_setup(self) -> bool:
        """
        Handle AWS credential setup when credentials are missing or invalid.
        
        Returns:
            True if credentials were successfully configured, False otherwise
        """
        console.print(Panel(
            "[red]AWS Credentials Required[/red]\n\n"
            "ThreatForest requires AWS credentials to access Bedrock services.\n\n"
            "[bold]Setup options:[/bold]\n"
            "1. Use AWS CLI: Run 'aws configure' in your terminal\n"
            "2. Environment variables: Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY\n"
            "3. IAM roles: Use EC2 instance profiles or ECS task roles\n"
            "4. AWS profiles: Set AWS_PROFILE environment variable\n\n"
            "[yellow]Please configure your credentials and then continue.[/yellow]",
            title="Credential Setup Required",
            border_style="red"
        ))
        
        while True:
            choice = Prompt.ask(
                "What would you like to do?",
                choices=["retry", "help", "cancel"],
                default="retry"
            )
            
            if choice == "cancel":
                return False
            elif choice == "help":
                self._show_credential_help()
                continue
            elif choice == "retry":
                # Re-test credentials
                credential_status = self.detect_aws_credentials()
                if credential_status.is_valid:
                    console.print("[green]✓ AWS credentials detected successfully![/green]")
                    return True
                else:
                    console.print(f"[red]✗ {credential_status.message}[/red]")
                    if not Confirm.ask("Try again?", default=True):
                        return False
    
    def _show_credential_help(self) -> None:
        """Show detailed help for AWS credential setup."""
        help_panel = Panel(
            "[bold]AWS Credential Setup Methods:[/bold]\n\n"
            "[bold cyan]1. AWS CLI (Recommended):[/bold cyan]\n"
            "   aws configure\n"
            "   # Follow prompts to enter your access key, secret key, and region\n\n"
            "[bold cyan]2. Environment Variables:[/bold cyan]\n"
            "   export AWS_ACCESS_KEY_ID=your_access_key\n"
            "   export AWS_SECRET_ACCESS_KEY=your_secret_key\n"
            "   export AWS_DEFAULT_REGION=us-east-1\n\n"
            "[bold cyan]3. AWS Profile:[/bold cyan]\n"
            "   export AWS_PROFILE=your_profile_name\n\n"
            "[bold cyan]4. IAM Roles (for EC2/ECS):[/bold cyan]\n"
            "   Attach appropriate IAM role to your instance/task\n\n"
            "[bold]Required Permissions:[/bold]\n"
            "• bedrock:InvokeModel\n"
            "• bedrock:ListFoundationModels\n"
            "• bedrock:GetFoundationModel",
            title="Credential Setup Help",
            border_style="blue"
        )
        console.print(help_panel)
    
    def _prompt_for_region(self) -> str:
        """
        Prompt user to select AWS region.
        
        Returns:
            Selected AWS region
        """
        console.print("\n[bold]Select AWS Region[/bold]")
        console.print("Choose the AWS region where you want to use Bedrock services.")
        
        # Common Bedrock regions
        regions = [
            ("us-east-1", "US East (N. Virginia) - Most models available"),
            ("us-west-2", "US West (Oregon) - Good model selection"),
            ("eu-west-1", "Europe (Ireland) - European data residency"),
            ("eu-central-1", "Europe (Frankfurt) - European data residency"),
            ("ap-southeast-1", "Asia Pacific (Singapore)"),
            ("ap-southeast-2", "Asia Pacific (Sydney)"),
            ("ap-northeast-1", "Asia Pacific (Tokyo)"),
            ("other", "Enter custom region")
        ]
        
        # Display region options
        table = Table(title="Available Regions", show_header=True, header_style="bold cyan")
        table.add_column("Option", style="cyan", no_wrap=True)
        table.add_column("Region", style="white")
        table.add_column("Description", style="dim")
        
        for i, (region_code, description) in enumerate(regions, 1):
            if region_code == "other":
                table.add_row(str(i), region_code, description)
            else:
                table.add_row(str(i), region_code, description)
        
        console.print(table)
        
        while True:
            try:
                choice = IntPrompt.ask(
                    "Select region",
                    default=1,
                    show_default=True
                )
                
                if 1 <= choice <= len(regions):
                    if choice == len(regions):  # "other" option
                        custom_region = Prompt.ask("Enter AWS region code")
                        if custom_region:
                            return custom_region
                    else:
                        return regions[choice - 1][0]
                else:
                    console.print("[red]Invalid choice. Please select a valid option.[/red]")
                    
            except (ValueError, KeyboardInterrupt):
                console.print("[red]Invalid input. Please enter a number.[/red]")
    
    def _filter_supported_models(self, models: List[Any]) -> List[Any]:
        """
        Filter out models that require inference profiles or are not supported.
        
        Args:
            models: List of ModelInfo objects
            
        Returns:
            Filtered list of supported models
        """
        # Models that require inference profiles (not directly invokable)
        inference_profile_models = {
            "anthropic.claude-sonnet-4-20250514-v1:0",
            "anthropic.claude-opus-4-20250514-v1:0", 
            "anthropic.claude-opus-4-1-20250805-v1:0",
            "anthropic.claude-3-7-sonnet-20250219-v1:0"
        }
        
        supported_models = []
        for model in models:
            # Skip models that require inference profiles
            if model.model_id in inference_profile_models:
                self.logger.debug(f"Filtering out {model.model_id} (requires inference profile)")
                continue
            
            # Only include active models
            if model.model_lifecycle_status != 'ACTIVE':
                self.logger.debug(f"Filtering out {model.model_id} (status: {model.model_lifecycle_status})")
                continue
            
            # Only include text models
            if 'TEXT' not in model.input_modalities or 'TEXT' not in model.output_modalities:
                self.logger.debug(f"Filtering out {model.model_id} (not text-based)")
                continue
            
            supported_models.append(model)
        
        return supported_models
    
    def _show_inference_profile_setup_guidance(self) -> None:
        """Show guidance for setting up inference profiles."""
        console.print(Panel(
            "[bold yellow]Setting Up Inference Profiles[/bold yellow]\n\n"
            "Inference profiles provide optimized access to foundation models and are required\n"
            "for some newer models like Claude Sonnet 4.\n\n"
            "[bold]To set up inference profiles:[/bold]\n"
            "1. Go to the AWS Bedrock console\n"
            "2. Navigate to 'Inference profiles' in the left menu\n"
            "3. Click 'Create inference profile'\n"
            "4. Select your desired models and configuration\n"
            "5. Choose throughput settings (On-demand or Provisioned)\n\n"
            "[bold]Benefits of inference profiles:[/bold]\n"
            "• Access to latest models (Claude Sonnet 4, Opus 4)\n"
            "• Optimized performance and throughput\n"
            "• Better cost management\n"
            "• Enhanced monitoring and logging\n\n"
            "[dim]For more information, visit the AWS Bedrock documentation.[/dim]",
            title="Inference Profile Setup",
            border_style="yellow"
        ))
    
    def _filter_text_inference_profiles(self, profiles: List[Any]) -> List[Any]:
        """
        Filter inference profiles to only include those with text-based models.
        
        Args:
            profiles: List of InferenceProfileInfo objects
            
        Returns:
            Filtered list of text-capable inference profiles
        """
        text_profiles = []
        
        for profile in profiles:
            # Check if profile has text-capable models
            has_text_model = False
            
            for model in profile.models:
                # Check if model supports text input/output
                model_id = model.get('modelId', '')
                
                # Common text model patterns
                if any(pattern in model_id.lower() for pattern in [
                    'claude', 'titan-text', 'jurassic', 'command', 'llama'
                ]):
                    has_text_model = True
                    break
            
            if has_text_model and profile.status == 'ACTIVE':
                text_profiles.append(profile)
                self.logger.debug(f"Including inference profile: {profile.inference_profile_id}")
            else:
                self.logger.debug(f"Filtering out inference profile: {profile.inference_profile_id} (no text models or inactive)")
        
        return text_profiles
    
    def _prompt_for_inference_profile(self, profiles: List[Any]) -> str:
        """
        Prompt user to select from available inference profiles.
        
        Args:
            profiles: List of InferenceProfileInfo objects
            
        Returns:
            Selected inference profile ID
        """
        console.print(f"\n[bold]Available Inference Profiles[/bold]")
        console.print("[dim]Inference profiles provide optimized access to foundation models.[/dim]")
        
        # Create table of inference profiles
        table = Table(title="Inference Profiles", show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim", width=3)
        table.add_column("Profile Name", style="bold")
        table.add_column("Profile ID", style="cyan")
        table.add_column("Models", style="green")
        table.add_column("Type", style="yellow")
        
        for i, profile in enumerate(profiles[:10], 1):  # Show top 10
            # Get model names from the profile
            model_names = []
            for model in profile.models[:3]:  # Show first 3 models
                model_id = model.get('modelId', 'Unknown')
                # Extract readable name from model ID
                if 'claude' in model_id:
                    if 'sonnet' in model_id:
                        model_names.append('Claude Sonnet')
                    elif 'haiku' in model_id:
                        model_names.append('Claude Haiku')
                    elif 'opus' in model_id:
                        model_names.append('Claude Opus')
                    else:
                        model_names.append('Claude')
                elif 'titan' in model_id:
                    model_names.append('Titan Text')
                else:
                    model_names.append(model_id.split('.')[-1] if '.' in model_id else model_id)
            
            if len(profile.models) > 3:
                model_names.append(f"... +{len(profile.models) - 3} more")
            
            models_str = ", ".join(model_names) if model_names else "Unknown"
            
            table.add_row(
                str(i),
                profile.inference_profile_name,
                profile.inference_profile_id,
                models_str,
                profile.type
            )
        
        # Add fallback option
        table.add_row(
            str(len(profiles) + 1),
            "Use regular models instead",
            "fallback",
            "Foundation models",
            "FALLBACK"
        )
        
        console.print(table)
        
        while True:
            try:
                choice = IntPrompt.ask(
                    f"\nSelect inference profile (1-{len(profiles) + 1})",
                    default=1
                )
                
                if 1 <= choice <= len(profiles):
                    selected_profile = profiles[choice - 1]
                    
                    # Show profile details
                    console.print(f"\n[green]Selected:[/green] {selected_profile.inference_profile_name}")
                    console.print(f"[dim]Profile ID:[/dim] {selected_profile.inference_profile_id}")
                    
                    if selected_profile.description:
                        console.print(f"[dim]Description:[/dim] {selected_profile.description}")
                    
                    # Show included models
                    console.print(f"[dim]Included models:[/dim]")
                    for model in selected_profile.models[:5]:  # Show first 5 models
                        model_id = model.get('modelId', 'Unknown')
                        console.print(f"  • {model_id}")
                    
                    if len(selected_profile.models) > 5:
                        console.print(f"  • ... and {len(selected_profile.models) - 5} more models")
                    
                    # Return the ARN if available, otherwise the profile ID
                    return selected_profile.inference_profile_arn or selected_profile.inference_profile_id
                
                elif choice == len(profiles) + 1:
                    # User chose to use regular models instead
                    console.print("\n[yellow]Falling back to regular foundation models...[/yellow]")
                    
                    # We need to discover regular models since we skipped that step
                    try:
                        # Get the bedrock client from the outer scope
                        temp_config = BedrockConfig(region=region)
                        bedrock_client = BedrockClient(temp_config)
                        
                        console.print("[dim]Discovering foundation models...[/dim]")
                        recommended_models = bedrock_client.get_model_recommendations("analysis")
                        
                        if not recommended_models:
                            all_models = bedrock_client.list_available_models()
                            recommended_models = self._filter_supported_models(all_models)
                        
                        self._available_models = self._filter_supported_models(recommended_models)
                        
                        if self._available_models:
                            return self._show_regular_model_selection()
                        else:
                            console.print("[yellow]No supported models found. Using fallback options...[/yellow]")
                            return self._prompt_for_fallback_model()
                            
                    except Exception as e:
                        self.logger.error(f"Failed to discover regular models: {e}")
                        console.print("[yellow]Model discovery failed. Using fallback options...[/yellow]")
                        return self._prompt_for_fallback_model()
                
                else:
                    console.print(f"[red]Please enter a number between 1 and {len(profiles) + 1}[/red]")
                    
            except (ValueError, KeyboardInterrupt):
                console.print("[red]Invalid input. Please enter a number.[/red]")
    
    def _prompt_for_regular_models(self) -> str:
        """
        Prompt for regular foundation model selection (fallback from inference profiles).
        
        Returns:
            Selected model ID
        """
        console.print("\n[yellow]Falling back to foundation models...[/yellow]")
        
        # Always use fallback models when called from inference profile selection
        return self._prompt_for_fallback_model()
    
    def _show_regular_model_selection(self) -> str:
        """
        Show regular model selection interface.
        
        Returns:
            Selected model ID
        """
        # Check if we have any models available
        if not self._available_models:
            console.print("\n[yellow]No supported models found. Using fallback options...[/yellow]")
            return self._prompt_for_fallback_model()
        
        # Display model options
        console.print(f"\nFound {len(self._available_models)} supported models:")
        console.print("[dim]Note: Models requiring inference profiles have been filtered out for direct use.[/dim]")
        
        table = Table(title="Supported Models", show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim", width=3)
        table.add_column("Model Name", style="bold")
        table.add_column("Provider", style="cyan")
        table.add_column("Status", style="yellow")
        
        for i, model in enumerate(self._available_models[:10], 1):  # Show top 10
            status = "✓ Active" if model.model_lifecycle_status == "ACTIVE" else model.model_lifecycle_status
            table.add_row(str(i), model.model_name, model.provider_name, status)
        
        # Add manual options
        table.add_row(str(len(self._available_models) + 1), "Inference Profile ARN", "Manual", "Enter ARN manually")
        table.add_row(str(len(self._available_models) + 2), "Custom model ID", "Manual", "Enter model ID manually")
        
        console.print(table)
        
        while True:
            try:
                choice = IntPrompt.ask(
                    f"Select model (1-{len(self._available_models) + 2})",
                    default=1
                )
                
                if 1 <= choice <= len(self._available_models):
                    selected_model = self._available_models[choice - 1]
                    
                    # Validate model availability
                    console.print(f"\n[green]Selected:[/green] {selected_model.model_name}")
                    console.print(f"[dim]Model ID:[/dim] {selected_model.model_id}")
                    console.print(f"[dim]Provider:[/dim] {selected_model.provider_name}")
                    
                    return selected_model.model_id
                
                elif choice == len(self._available_models) + 1:
                    # Manual inference profile ARN
                    return self._prompt_for_manual_inference_profile_arn()
                
                elif choice == len(self._available_models) + 2:
                    # Custom model ID
                    custom_model = Prompt.ask("Enter model ID")
                    if custom_model.strip():
                        console.print(f"[yellow]Using custom model:[/yellow] {custom_model}")
                        return custom_model.strip()
                    else:
                        console.print("[red]Model ID cannot be empty[/red]")
                
                else:
                    console.print(f"[red]Please enter a number between 1 and {len(self._available_models) + 2}[/red]")
                    
            except (ValueError, KeyboardInterrupt):
                console.print("[red]Invalid input. Please enter a number.[/red]")
    
    def _prompt_for_model(self, region: str) -> str:
        """
        Prompt user to select Bedrock model or inference profile.
        
        Args:
            region: AWS region for model discovery
            
        Returns:
            Selected model ID or inference profile ID
        """
        _import_bedrock_classes()  # Lazy import
        
        console.print(f"\n[bold]Select Bedrock Model or Inference Profile[/bold]")
        console.print(f"Discovering available options in region: {region}")
        
        # Create temporary Bedrock client for discovery
        temp_config = BedrockConfig(region=region)
        
        # First, try to discover inference profiles
        inference_profiles = []
        text_profiles = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Discovering options...", total=None)
            
            try:
                bedrock_client = BedrockClient(temp_config)
                
                progress.update(task, description="Checking for inference profiles...")
                try:
                    inference_profiles = bedrock_client.list_inference_profiles()
                    
                    # Filter inference profiles for text-based models
                    text_profiles = self._filter_text_inference_profiles(inference_profiles)
                    
                except Exception as profile_error:
                    # Log the specific error but don't fail the setup
                    self.logger.warning(f"Could not list inference profiles: {profile_error}")
                    inference_profiles = []
                    text_profiles = []
                    
            except Exception as client_error:
                # Failed to create Bedrock client
                self.logger.error(f"Failed to create Bedrock client: {client_error}")
                inference_profiles = []
                text_profiles = []
        
        # Handle inference profile results outside of progress context
        if text_profiles:
            # If we have inference profiles, offer them as the primary option
            console.print(f"\n[green]Found {len(text_profiles)} inference profiles with text models![/green]")
            console.print("[dim]Inference profiles provide optimized performance and may include newer models.[/dim]")
            
            # Ask user if they want to use inference profiles or regular models
            use_profiles = Confirm.ask(
                "\nWould you like to use inference profiles? (Recommended for best performance)",
                default=True
            )
            
            if use_profiles:
                return self._prompt_for_inference_profile(text_profiles)
        
        elif inference_profiles:
            console.print(f"\n[yellow]Found {len(inference_profiles)} inference profiles, but none support text models.[/yellow]")
            
            # Offer manual inference profile ARN entry
            if Confirm.ask("\nDo you have a text-capable inference profile ARN you'd like to use?", default=False):
                return self._prompt_for_manual_inference_profile_arn()
            
            console.print("[dim]Falling back to foundation models...[/dim]")
            
            # Offer to show setup guidance
            if Confirm.ask("\nWould you like to see how to set up text-capable inference profiles?", default=False):
                self._show_inference_profile_setup_guidance()
        
        else:
            console.print(f"\n[yellow]Inference profiles not available in this region.[/yellow]")
            console.print("[dim]This is normal if your account doesn't have inference profiles configured.[/dim]")
            
            # Offer manual inference profile ARN entry
            if Confirm.ask("\nDo you have an inference profile ARN you'd like to use?", default=False):
                return self._prompt_for_manual_inference_profile_arn()
            
            console.print("[dim]Continuing with foundation models...[/dim]")
            
            # Offer to show setup guidance for inference profiles
            if Confirm.ask("\nWould you like to see how to set up inference profiles for access to newer models?", default=False):
                self._show_inference_profile_setup_guidance()
        
        # Continue with regular model discovery
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Getting model recommendations...", total=None)
            
            try:
                # Fall back to regular model discovery
                progress.update(task, description="Getting model recommendations...")
                try:
                    recommended_models = bedrock_client.get_model_recommendations("analysis")
                    
                    if not recommended_models:
                        # Fallback to all available models
                        progress.update(task, description="Loading all available models...")
                        all_models = bedrock_client.list_available_models()
                        recommended_models = self._filter_supported_models(all_models)
                    
                    # Filter out models that require inference profiles
                    self._available_models = self._filter_supported_models(recommended_models)
                    
                    self.logger.info(f"Found {len(self._available_models)} available models after filtering")
                    
                except Exception as model_error:
                    self.logger.error(f"Failed to discover regular models: {model_error}")
                    console.print(f"[red]Failed to discover models: {model_error}[/red]")
                    
                    # Offer manual inference profile ARN entry first
                    if Confirm.ask("\nDo you have an inference profile ARN you'd like to use instead?", default=False):
                        return self._prompt_for_manual_inference_profile_arn()
                    
                    console.print("[yellow]Using fallback model options...[/yellow]")
                    return self._prompt_for_fallback_model()
                
            except Exception as e:
                # Check if it's a BedrockClientError (either real or mock)
                is_bedrock_error = (
                    (BedrockClientError and isinstance(e, BedrockClientError)) or
                    (hasattr(e, '__class__') and e.__class__.__name__ == "BedrockClientError")
                )
                
                if is_bedrock_error:
                    self.logger.error(f"Failed to discover options: {e}")
                    console.print(f"[red]Failed to discover options: {e}[/red]")
                    
                    # Offer manual inference profile ARN entry first
                    if Confirm.ask("\nDo you have an inference profile ARN you'd like to use instead?", default=False):
                        return self._prompt_for_manual_inference_profile_arn()
                    
                    # Provide fallback options
                    console.print("[yellow]Using default model options...[/yellow]")
                    return self._prompt_for_fallback_model()
                else:
                    # Re-raise if it's not a BedrockClientError
                    raise
        
        if not self._available_models:
            console.print("[yellow]No models discovered.[/yellow]")
            
            # Offer manual inference profile ARN entry first
            if Confirm.ask("\nDo you have an inference profile ARN you'd like to use instead?", default=False):
                return self._prompt_for_manual_inference_profile_arn()
            
            console.print("[yellow]Using default model options...[/yellow]")
            return self._prompt_for_fallback_model()
        
        # Use the regular model selection interface
        return self._show_regular_model_selection()
    
    def _prompt_for_manual_inference_profile_arn(self) -> str:
        """
        Prompt user to manually enter an inference profile ARN.
        
        Returns:
            Inference profile ARN
        """
        console.print("\n[bold cyan]Manual Inference Profile ARN Entry[/bold cyan]")
        console.print("[dim]Enter the full ARN of your inference profile.[/dim]")
        console.print("[dim]Example: arn:aws:bedrock:us-east-1:123456789012:inference-profile/my-profile[/dim]")
        
        while True:
            arn = Prompt.ask("\nInference Profile ARN")
            
            if not arn.strip():
                console.print("[red]ARN cannot be empty.[/red]")
                continue
            
            # Basic ARN validation
            if not arn.startswith("arn:aws:bedrock:"):
                console.print("[red]Invalid ARN format. Must start with 'arn:aws:bedrock:'[/red]")
                if Confirm.ask("Continue anyway?", default=False):
                    return arn.strip()
                continue
            
            if ":inference-profile/" not in arn:
                console.print("[red]ARN doesn't appear to be an inference profile. Must contain ':inference-profile/'[/red]")
                if Confirm.ask("Continue anyway?", default=False):
                    return arn.strip()
                continue
            
            # Show confirmation
            console.print(f"\n[green]Inference Profile ARN:[/green] {arn}")
            console.print("[dim]This will be used to access the model through the inference profile.[/dim]")
            
            if Confirm.ask("Use this inference profile ARN?", default=True):
                return arn.strip()
            
            # Ask if they want to try again or cancel
            if not Confirm.ask("Try entering a different ARN?", default=True):
                # User wants to cancel, fall back to foundation models
                console.print("[yellow]Falling back to foundation model selection...[/yellow]")
                return self._prompt_for_fallback_model()

    def _prompt_for_fallback_model(self) -> str:
        """
        Prompt for model selection when discovery fails.
        
        Returns:
            Selected model ID
        """
        fallback_models = [
            "anthropic.claude-3-5-sonnet-20241022-v2:0",
            "anthropic.claude-3-sonnet-20240229-v1:0",
            "anthropic.claude-3-haiku-20240307-v1:0",
            "anthropic.claude-v2:1",
            "amazon.titan-text-express-v1"
        ]
        
        console.print("Select from common models:")
        for i, model in enumerate(fallback_models, 1):
            console.print(f"  {i}. {model}")
        
        console.print(f"  {len(fallback_models) + 1}. Enter inference profile ARN")
        console.print(f"  {len(fallback_models) + 2}. Enter custom model ID")
        
        while True:
            try:
                choice = IntPrompt.ask("Select model", default=1)
                
                if 1 <= choice <= len(fallback_models):
                    return fallback_models[choice - 1]
                elif choice == len(fallback_models) + 1:
                    # Manual inference profile ARN
                    return self._prompt_for_manual_inference_profile_arn()
                elif choice == len(fallback_models) + 2:
                    custom_model = Prompt.ask("Enter model ID")
                    if custom_model:
                        return custom_model
                else:
                    console.print("[red]Invalid choice.[/red]")
                    
            except (ValueError, KeyboardInterrupt):
                console.print("[red]Invalid input.[/red]")
    
    def _prompt_for_model_parameters(self) -> Dict[str, Any]:
        """
        Prompt for model parameters configuration.
        
        Returns:
            Dictionary with model parameters
        """
        console.print("\n[bold]Model Parameters[/bold]")
        console.print("Configure model behavior parameters (or use defaults).")
        
        if not Confirm.ask("Configure advanced parameters?", default=False):
            return {
                'temperature': 0.1,
                'max_tokens': 4000,
                'top_p': 0.9
            }
        
        # Temperature
        temperature = FloatPrompt.ask(
            "Temperature (0.0-1.0, lower = more focused)",
            default=0.1,
            show_default=True
        )
        temperature = max(0.0, min(1.0, temperature))
        
        # Max tokens
        max_tokens = IntPrompt.ask(
            "Maximum tokens (1-100000)",
            default=4000,
            show_default=True
        )
        max_tokens = max(1, min(100000, max_tokens))
        
        # Top-p
        top_p = FloatPrompt.ask(
            "Top-p (0.0-1.0, nucleus sampling)",
            default=0.9,
            show_default=True
        )
        top_p = max(0.0, min(1.0, top_p))
        
        return {
            'temperature': temperature,
            'max_tokens': max_tokens,
            'top_p': top_p
        }
    
    def _configure_additional_settings(self) -> Dict[str, Any]:
        """
        Configure additional ThreatForest settings.
        
        Returns:
            Dictionary with additional configuration
        """
        console.print("\n[bold]Additional Settings[/bold]")
        
        config = {}
        
        # Output directory
        if Confirm.ask("Configure output directory?", default=False):
            output_dir = Prompt.ask("Output directory", default="./tf-output")
            config['output'] = {'directory': output_dir}
        
        # Processing settings
        if Confirm.ask("Configure processing settings?", default=False):
            severity = Prompt.ask(
                "Severity threshold",
                choices=["low", "medium", "high"],
                default="high"
            )
            
            max_agents = IntPrompt.ask(
                "Maximum concurrent agents",
                default=4,
                show_default=True
            )
            
            config['processing'] = {
                'severity_threshold': severity,
                'max_concurrent_agents': max_agents
            }
        
        return config
    
    def _prompt_for_configuration_scope(self) -> str:
        """
        Prompt user for configuration scope (user vs project level).
        
        Returns:
            Configuration scope ('user' or 'project')
        """
        console.print("\n[bold]Configuration Scope[/bold]")
        console.print("Choose where to save your configuration:")
        console.print("• [cyan]User level[/cyan]: Available across all projects (~/.tf/config.yaml)")
        console.print("• [cyan]Project level[/cyan]: Only for this project (.tf/config.yaml)")
        
        scope = Prompt.ask(
            "Configuration scope",
            choices=["user", "project"],
            default="project"
        )
        
        return scope
    
    def _show_test_results(self, validation_result: ValidationResult) -> None:
        """
        Display configuration test results.
        
        Args:
            validation_result: Validation results to display
        """
        if validation_result.is_valid:
            console.print(Panel(
                "[bold green]✓ Configuration Test Passed![/bold green]\n\n"
                "All components validated successfully:\n"
                + "\n".join([f"• {component}: {'✓' if status else '✗'}" 
                           for component, status in validation_result.tested_components.items()]),
                title="Test Results",
                border_style="green"
            ))
        else:
            console.print(Panel(
                "[bold red]✗ Configuration Test Failed[/bold red]\n\n"
                f"Found {len(validation_result.errors)} error(s):\n"
                + "\n".join([f"• {error.component}: {error.message}" 
                           for error in validation_result.errors]),
                title="Test Results",
                border_style="red"
            ))
            
            if validation_result.warnings:
                console.print(f"\n[yellow]Warnings ({len(validation_result.warnings)}):[/yellow]")
                for warning in validation_result.warnings:
                    console.print(f"  • {warning.component}: {warning.message}")
    
    def _handle_validation_errors(self, validation_result: ValidationResult) -> bool:
        """
        Handle configuration validation errors.
        
        Args:
            validation_result: Validation results with errors
            
        Returns:
            True if errors were resolved, False otherwise
        """
        console.print("\n[bold red]Configuration Issues Found[/bold red]")
        
        for error in validation_result.errors:
            console.print(f"\n[red]Error in {error.component}:[/red] {error.message}")
            if hasattr(error, 'suggestion') and error.suggestion:
                console.print(f"[dim]Suggestion: {error.suggestion}[/dim]")
        
        return Confirm.ask("\nContinue with current configuration anyway?", default=False)
    
    def _show_completion_screen(self, config: ThreatForestConfig, scope: str) -> None:
        """
        Show setup completion screen.
        
        Args:
            config: Final configuration
            scope: Configuration scope
        """
        config_path = "~/.tf/config.yaml" if scope == "user" else ".tf/config.yaml"
        
        completion_panel = Panel(
            "[bold green]🎉 Setup Complete![/bold green]\n\n"
            f"ThreatForest has been configured successfully.\n\n"
            f"[bold]Configuration saved to:[/bold] {config_path}\n"
            f"[bold]Region:[/bold] {config.bedrock.region}\n"
            f"[bold]Model:[/bold] {config.bedrock.model}\n"
            f"[bold]Output:[/bold] {config.output.directory}\n\n"
            "[bold cyan]Next steps:[/bold cyan]\n"
            "• Run 'tf analyze' to start analyzing your project\n"
            "• Use 'tf status' to check system status\n"
            "• Use 'tf config show' to view your configuration\n\n"
            "[dim]You can re-run this setup anytime with 'tf setup'[/dim]",
            title="Setup Complete",
            border_style="green"
        )
        console.print(completion_panel)
    
    def _get_credential_source(self) -> str:
        """
        Determine the source of AWS credentials.
        
        Returns:
            String describing credential source
        """
        if os.getenv('AWS_ACCESS_KEY_ID') and os.getenv('AWS_SECRET_ACCESS_KEY'):
            return "environment_variables"
        elif os.getenv('AWS_PROFILE'):
            return f"aws_profile_{os.getenv('AWS_PROFILE')}"
        else:
            return "aws_config_file"


class CredentialStatus:
    """Status of AWS credential detection and validation."""
    
    def __init__(
        self,
        is_valid: bool,
        error_type: Optional[str] = None,
        message: Optional[str] = None,
        suggestion: Optional[str] = None,
        account_id: Optional[str] = None,
        user_arn: Optional[str] = None,
        user_id: Optional[str] = None,
        detection_method: Optional[str] = None
    ):
        self.is_valid = is_valid
        self.error_type = error_type
        self.message = message
        self.suggestion = suggestion
        self.account_id = account_id
        self.user_arn = user_arn
        self.user_id = user_id
        self.detection_method = detection_method