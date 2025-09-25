"""
Configuration management system for ThreatForest.

This module provides hierarchical configuration loading from multiple sources:
- Command-line arguments (highest priority)
- Environment variables
- Project-level config file (.tf/config.yaml)
- User-level config file (~/.tf/config.yaml)
- Default values (lowest priority)
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
from pydantic import BaseModel, Field
from dataclasses import dataclass
from enum import Enum

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError


class BedrockConfig(BaseModel):
    """Configuration for Amazon Bedrock integration."""
    
    region: str = Field(
        default="us-east-1",
        description="AWS region for Bedrock API"
    )
    model: str = Field(
        default="anthropic.claude-3-sonnet-20240229-v1:0",
        description="Bedrock model to use for AI processing"
    )
    api_key_source: str = Field(
        default="environment",
        description="Source for API key (environment, file, parameter)"
    )
    timeout_seconds: int = Field(
        default=300,
        description="Timeout for Bedrock API calls"
    )
    
    # New enhanced configuration parameters
    temperature: float = Field(
        default=0.1,
        ge=0.0,
        le=1.0,
        description="Temperature parameter for model inference (0.0-1.0)"
    )
    max_tokens: int = Field(
        default=4000,
        ge=1,
        le=100000,
        description="Maximum number of tokens to generate"
    )
    top_p: float = Field(
        default=0.9,
        ge=0.0,
        le=1.0,
        description="Top-p parameter for nucleus sampling (0.0-1.0)"
    )
    custom_parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Custom parameters for advanced model configuration"
    )
    validation_status: str = Field(
        default="unknown",
        description="Status of configuration validation (unknown, valid, invalid)"
    )
    last_validated: Optional[datetime] = Field(
        default=None,
        description="Timestamp of last configuration validation"
    )


class ProcessingConfig(BaseModel):
    """Configuration for threat processing."""
    
    severity_threshold: str = Field(
        default="high",
        description="Minimum severity level to process (low, medium, high)"
    )
    max_concurrent_agents: int = Field(
        default=4,
        description="Maximum number of concurrent agents"
    )
    timeout_seconds: int = Field(
        default=300,
        description="Timeout for agent processing"
    )


class OutputConfig(BaseModel):
    """Configuration for output generation."""
    
    directory: str = Field(
        default="./tf-output",
        description="Output directory for generated files"
    )
    format: str = Field(
        default="mermaid",
        description="Output format for attack trees"
    )
    include_summary: bool = Field(
        default=True,
        description="Whether to include summary report"
    )


class FileConfig(BaseModel):
    """Configuration for file processing."""
    
    context_patterns: List[str] = Field(
        default_factory=lambda: [
            "README*",
            "readme*",
            "architecture.*",
            "dataflow.*",
            "threats.*",
            "threat-*.json"
        ],
        description="File patterns to scan for context"
    )


class TTCConfig(BaseModel):
    """Configuration for TTC mapping."""
    
    aaf_bundle_path: str = Field(
        default="./aaf-bundle.json",
        description="Path to AAF bundle JSON file"
    )
    alignment_threshold: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Minimum alignment score for TTC mapping"
    )
    enable_enhancement: bool = Field(
        default=True,
        description="Whether to enable TTC enhancement"
    )


class ValidationStatus(str, Enum):
    """Validation status enumeration."""
    UNKNOWN = "unknown"
    VALID = "valid"
    INVALID = "invalid"
    PENDING = "pending"


@dataclass
class ValidationError:
    """Represents a configuration validation error."""
    component: str
    error_type: str
    message: str
    suggestion: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of configuration validation."""
    is_valid: bool
    errors: List[ValidationError]
    warnings: List[ValidationError]
    tested_components: Dict[str, bool]
    validation_time: datetime


class ThreatForestConfig(BaseModel):
    """Main configuration model for ThreatForest."""
    
    bedrock: BedrockConfig = Field(
        default_factory=BedrockConfig,
        description="Bedrock configuration"
    )
    processing: ProcessingConfig = Field(
        default_factory=ProcessingConfig,
        description="Processing configuration"
    )
    output: OutputConfig = Field(
        default_factory=OutputConfig,
        description="Output configuration"
    )
    files: FileConfig = Field(
        default_factory=FileConfig,
        description="File processing configuration"
    )
    ttc: TTCConfig = Field(
        default_factory=TTCConfig,
        description="TTC mapping configuration"
    )


class ConfigManager:
    """
    Manages hierarchical configuration loading for ThreatForest.
    
    Configuration is loaded in order of priority:
    1. Command-line arguments (highest)
    2. Environment variables
    3. Project-level config file
    4. User-level config file
    5. Default values (lowest)
    """
    
    def __init__(self, project_dir: Optional[str] = None):
        """
        Initialize ConfigManager.
        
        Args:
            project_dir: Project directory to look for config files
        """
        self.project_dir = Path(project_dir) if project_dir else Path.cwd()
        self._config: Optional[ThreatForestConfig] = None
        self.logger = logging.getLogger(__name__)
    
    def load_config(
        self,
        cli_args: Optional[Dict[str, Any]] = None,
        config_file: Optional[str] = None
    ) -> ThreatForestConfig:
        """
        Load configuration from all sources.
        
        Args:
            cli_args: Command-line arguments dictionary
            config_file: Explicit config file path
            
        Returns:
            Loaded ThreatForestConfig instance
        """
        self.logger.info("Starting configuration loading process")
        
        # Start with default configuration
        config_data = {}
        
        # Load user-level config file
        self.logger.debug("Loading user-level configuration")
        user_config = self._load_user_config()
        if user_config:
            self.logger.info(f"Loaded user-level config with {len(user_config)} sections")
            config_data.update(user_config)
        else:
            self.logger.debug("No user-level configuration found")
        
        # Load project-level config file
        self.logger.debug("Loading project-level configuration")
        project_config = self._load_project_config(config_file)
        if project_config:
            self.logger.info(f"Loaded project-level config with {len(project_config)} sections")
            config_data.update(project_config)
        else:
            self.logger.debug("No project-level configuration found")
        
        # Load environment variables
        self.logger.debug("Loading environment variable configuration")
        env_config = self._load_env_config()
        if env_config:
            self.logger.info(f"Loaded environment config with {len(env_config)} sections")
            config_data.update(env_config)
        else:
            self.logger.debug("No environment variable configuration found")
        
        # Apply CLI arguments (highest priority)
        if cli_args:
            self.logger.info(f"Applying CLI arguments with {len(cli_args)} sections")
            config_data.update(cli_args)
        
        # Create and cache configuration
        try:
            self._config = ThreatForestConfig(**config_data)
            self.logger.info("Configuration loaded successfully")
            
            # Log Bedrock configuration details
            bedrock_config = self._config.bedrock
            self.logger.debug(f"Bedrock configuration: region={bedrock_config.region}, "
                            f"model={bedrock_config.model}, temperature={bedrock_config.temperature}, "
                            f"max_tokens={bedrock_config.max_tokens}, top_p={bedrock_config.top_p}")
            
            if bedrock_config.custom_parameters:
                self.logger.debug(f"Custom parameters: {bedrock_config.custom_parameters}")
            
            return self._config
        except Exception as e:
            self.logger.error(f"Failed to create configuration: {e}")
            raise
    
    def get_config(self) -> ThreatForestConfig:
        """
        Get the current configuration.
        
        Returns:
            Current ThreatForestConfig instance
            
        Raises:
            RuntimeError: If configuration hasn't been loaded
        """
        if self._config is None:
            raise RuntimeError("Configuration not loaded. Call load_config() first.")
        return self._config
    
    def _load_user_config(self) -> Optional[Dict[str, Any]]:
        """Load user-level configuration file."""
        user_config_path = Path.home() / ".tf" / "config.yaml"
        return self._load_yaml_file(user_config_path)
    
    def _load_project_config(self, config_file: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Load project-level configuration file."""
        if config_file:
            config_path = Path(config_file)
        else:
            config_path = self.project_dir / ".tf" / "config.yaml"
        
        return self._load_yaml_file(config_path)
    
    def _load_yaml_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Load YAML configuration file.
        
        Args:
            file_path: Path to YAML file
            
        Returns:
            Configuration dictionary or None if file doesn't exist
        """
        if not file_path.exists():
            self.logger.debug(f"Configuration file not found: {file_path}")
            return None
        
        try:
            self.logger.debug(f"Loading configuration from: {file_path}")
            with open(file_path, 'r') as f:
                config_data = yaml.safe_load(f) or {}
            self.logger.debug(f"Successfully loaded {len(config_data)} configuration sections from {file_path}")
            return config_data
        except (yaml.YAMLError, IOError) as e:
            self.logger.error(f"Error loading config file {file_path}: {e}")
            raise ValueError(f"Error loading config file {file_path}: {e}")
    
    def _load_env_config(self) -> Dict[str, Any]:
        """
        Load configuration from environment variables.
        
        Environment variables should be prefixed with TF_ and use underscores
        to separate section and field names. For example:
        - TF_BEDROCK_REGION=us-west-2
        - TF_BEDROCK_TIMEOUT_SECONDS=300
        - TF_PROCESSING_SEVERITY_THRESHOLD=medium
        """
        config = {}
        
        for key, value in os.environ.items():
            if not key.startswith('TF_'):
                continue
            
            # Remove TF_ prefix and convert to lowercase
            config_key = key[3:].lower()
            
            # Split only on the first underscore to separate section from field
            if '_' in config_key:
                section, field = config_key.split('_', 1)
                
                if section not in config:
                    config[section] = {}
                
                config[section][field] = self._convert_env_value(value)
            else:
                config[config_key] = self._convert_env_value(value)
        
        return config
    
    def _convert_env_value(self, value: str) -> Any:
        """
        Convert environment variable string to appropriate type.
        
        Args:
            value: Environment variable value
            
        Returns:
            Converted value (bool, int, float, or str)
        """
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
    
    def save_config(
        self,
        config: ThreatForestConfig,
        file_path: Optional[str] = None,
        user_level: bool = False
    ) -> None:
        """
        Save configuration to file.
        
        Args:
            config: Configuration to save
            file_path: Explicit file path (overrides user_level)
            user_level: If True, save to user-level config
        """
        if file_path:
            config_path = Path(file_path)
        elif user_level:
            config_path = Path.home() / ".tf" / "config.yaml"
        else:
            config_path = self.project_dir / ".tf" / "config.yaml"
        
        self.logger.info(f"Saving configuration to: {config_path}")
        
        # Create directory if it doesn't exist
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert config to dictionary and save as YAML
        config_dict = config.model_dump()
        
        try:
            with open(config_path, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            self.logger.info(f"Configuration saved successfully to: {config_path}")
            
            # Log Bedrock configuration details that were saved
            bedrock_config = config.bedrock
            self.logger.debug(f"Saved Bedrock configuration: region={bedrock_config.region}, "
                            f"model={bedrock_config.model}, temperature={bedrock_config.temperature}, "
                            f"max_tokens={bedrock_config.max_tokens}, top_p={bedrock_config.top_p}, "
                            f"validation_status={bedrock_config.validation_status}")
            
        except IOError as e:
            self.logger.error(f"Error saving config file {config_path}: {e}")
            raise ValueError(f"Error saving config file {config_path}: {e}")
    
    def update_config(self, updates: Dict[str, Any]) -> ThreatForestConfig:
        """
        Update current configuration with new values.
        
        Args:
            updates: Dictionary of configuration updates
            
        Returns:
            Updated ThreatForestConfig instance
        """
        if self._config is None:
            raise RuntimeError("Configuration not loaded. Call load_config() first.")
        
        # Get current config as dict
        current_dict = self._config.model_dump()
        
        # Apply updates
        self._deep_update(current_dict, updates)
        
        # Create new config instance
        self._config = ThreatForestConfig(**current_dict)
        return self._config
    
    def _deep_update(self, base_dict: Dict[str, Any], update_dict: Dict[str, Any]) -> None:
        """
        Recursively update nested dictionary.
        
        Args:
            base_dict: Base dictionary to update
            update_dict: Updates to apply
        """
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value
    
    def validate_configuration(self, config: Optional[ThreatForestConfig] = None) -> ValidationResult:
        """
        Validate the current or provided configuration.
        
        This method performs comprehensive validation of the ThreatForest configuration,
        including AWS credentials, Bedrock connectivity, and configuration parameters.
        
        Args:
            config: Configuration to validate (defaults to current config)
            
        Returns:
            ValidationResult with detailed validation information
        """
        self.logger.info("Starting configuration validation")
        
        # Use provided config or current config
        if config is None:
            if self._config is None:
                self.logger.error("No configuration loaded for validation")
                return ValidationResult(
                    is_valid=False,
                    errors=[ValidationError(
                        component="config_manager",
                        error_type="no_config",
                        message="No configuration loaded. Call load_config() first.",
                        suggestion="Load configuration before validation"
                    )],
                    warnings=[],
                    tested_components={"config_manager": False},
                    validation_time=datetime.now()
                )
            config = self._config
        
        errors = []
        warnings = []
        tested_components = {}
        
        # Validate AWS credentials
        self.logger.info("Validating AWS credentials")
        credential_result = self._validate_aws_credentials()
        tested_components["aws_credentials"] = credential_result["is_valid"]
        
        if not credential_result["is_valid"]:
            errors.append(ValidationError(
                component="aws_credentials",
                error_type=credential_result["error_type"],
                message=credential_result["message"],
                suggestion=credential_result["suggestion"]
            ))
            self.logger.error(f"AWS credential validation failed: {credential_result['message']}")
        else:
            self.logger.info("AWS credentials validation successful")
        
        # Validate Bedrock configuration and connectivity
        self.logger.info("Validating Bedrock configuration")
        bedrock_result = self._validate_bedrock_configuration(config.bedrock)
        tested_components["bedrock_config"] = bedrock_result["is_valid"]
        
        if not bedrock_result["is_valid"]:
            errors.extend([ValidationError(
                component="bedrock_config",
                error_type=error["error_type"],
                message=error["message"],
                suggestion=error.get("suggestion")
            ) for error in bedrock_result["errors"]])
            self.logger.error(f"Bedrock configuration validation failed with {len(bedrock_result['errors'])} errors")
        else:
            self.logger.info("Bedrock configuration validation successful")
        
        # Add warnings from bedrock validation
        if bedrock_result.get("warnings"):
            warnings.extend([ValidationError(
                component="bedrock_config",
                error_type=warning["error_type"],
                message=warning["message"],
                suggestion=warning.get("suggestion")
            ) for warning in bedrock_result["warnings"]])
        
        # Test Bedrock connectivity if credentials and config are valid
        if credential_result["is_valid"] and bedrock_result["is_valid"]:
            self.logger.info("Testing Bedrock connectivity")
            connectivity_result = self._test_bedrock_connectivity(config.bedrock)
            tested_components["bedrock_connectivity"] = connectivity_result["is_valid"]
            
            if not connectivity_result["is_valid"]:
                errors.append(ValidationError(
                    component="bedrock_connectivity",
                    error_type=connectivity_result["error_type"],
                    message=connectivity_result["message"],
                    suggestion=connectivity_result["suggestion"]
                ))
                self.logger.error(f"Bedrock connectivity test failed: {connectivity_result['message']}")
            else:
                self.logger.info("Bedrock connectivity test successful")
        else:
            self.logger.warning("Skipping Bedrock connectivity test due to credential or configuration issues")
            tested_components["bedrock_connectivity"] = False
        
        # Validate other configuration sections
        self.logger.debug("Validating other configuration sections")
        other_result = self._validate_other_config_sections(config)
        tested_components.update(other_result["tested_components"])
        
        if other_result["warnings"]:
            warnings.extend([ValidationError(
                component=warning["component"],
                error_type=warning["error_type"],
                message=warning["message"],
                suggestion=warning.get("suggestion")
            ) for warning in other_result["warnings"]])
        
        # Determine overall validation status
        is_valid = len(errors) == 0
        validation_time = datetime.now()
        
        # Update configuration validation status
        if hasattr(config, 'bedrock'):
            config.bedrock.validation_status = ValidationStatus.VALID.value if is_valid else ValidationStatus.INVALID.value
            config.bedrock.last_validated = validation_time
        
        self.logger.info(f"Configuration validation completed: valid={is_valid}, "
                        f"errors={len(errors)}, warnings={len(warnings)}")
        
        return ValidationResult(
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            tested_components=tested_components,
            validation_time=validation_time
        )
    
    def _validate_aws_credentials(self) -> Dict[str, Any]:
        """
        Validate AWS credentials using boto3 session.
        
        Returns:
            Dictionary with validation result and details
        """
        self.logger.debug("Checking AWS credentials availability")
        
        try:
            # Create a boto3 session to test credentials
            session = boto3.Session()
            
            # Try to get credentials - this will raise an exception if not available
            credentials = session.get_credentials()
            
            if credentials is None:
                self.logger.warning("No AWS credentials found")
                return {
                    "is_valid": False,
                    "error_type": "no_credentials",
                    "message": "No AWS credentials found",
                    "suggestion": "Configure AWS credentials using 'aws configure', environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY), or IAM roles"
                }
            
            # Test if credentials are accessible
            if not credentials.access_key or not credentials.secret_key:
                self.logger.warning("AWS credentials are incomplete")
                return {
                    "is_valid": False,
                    "error_type": "incomplete_credentials",
                    "message": "AWS credentials are incomplete (missing access key or secret key)",
                    "suggestion": "Ensure both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set, or use 'aws configure'"
                }
            
            # Try to use credentials with a simple STS call
            sts_client = session.client('sts')
            identity = sts_client.get_caller_identity()
            
            self.logger.debug(f"AWS credentials validated for account: {identity.get('Account', 'unknown')}")
            
            return {
                "is_valid": True,
                "account_id": identity.get('Account'),
                "user_arn": identity.get('Arn'),
                "user_id": identity.get('UserId')
            }
            
        except NoCredentialsError:
            self.logger.warning("No AWS credentials configured")
            return {
                "is_valid": False,
                "error_type": "no_credentials",
                "message": "No AWS credentials configured",
                "suggestion": "Configure AWS credentials using 'aws configure', environment variables, or IAM roles"
            }
        
        except PartialCredentialsError as e:
            self.logger.warning(f"Partial AWS credentials: {e}")
            return {
                "is_valid": False,
                "error_type": "partial_credentials",
                "message": f"Partial AWS credentials: {e}",
                "suggestion": "Ensure all required credential components are provided"
            }
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            
            self.logger.warning(f"AWS credential validation failed: {error_code} - {error_message}")
            
            if error_code == 'InvalidUserID.NotFound':
                return {
                    "is_valid": False,
                    "error_type": "invalid_credentials",
                    "message": "AWS credentials are invalid or expired",
                    "suggestion": "Refresh your AWS credentials or check if they have expired"
                }
            elif error_code == 'AccessDenied':
                return {
                    "is_valid": False,
                    "error_type": "access_denied",
                    "message": "AWS credentials lack necessary permissions",
                    "suggestion": "Ensure your AWS credentials have the necessary permissions for STS and Bedrock services"
                }
            else:
                return {
                    "is_valid": False,
                    "error_type": "credential_error",
                    "message": f"AWS credential validation error: {error_message}",
                    "suggestion": "Check your AWS credentials and network connectivity"
                }
        
        except Exception as e:
            self.logger.error(f"Unexpected error validating AWS credentials: {e}")
            return {
                "is_valid": False,
                "error_type": "unexpected_error",
                "message": f"Unexpected error validating AWS credentials: {e}",
                "suggestion": "Check your AWS configuration and network connectivity"
            }
    
    def _validate_bedrock_configuration(self, bedrock_config: BedrockConfig) -> Dict[str, Any]:
        """
        Validate Bedrock configuration parameters.
        
        Args:
            bedrock_config: Bedrock configuration to validate
            
        Returns:
            Dictionary with validation result and details
        """
        self.logger.debug("Validating Bedrock configuration parameters")
        
        errors = []
        warnings = []
        
        # Validate region
        valid_regions = [
            'us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1'
        ]
        
        if bedrock_config.region not in valid_regions:
            warnings.append({
                "error_type": "unsupported_region",
                "message": f"Region '{bedrock_config.region}' may not support all Bedrock models",
                "suggestion": f"Consider using one of the well-supported regions: {', '.join(valid_regions[:3])}"
            })
            self.logger.warning(f"Bedrock region '{bedrock_config.region}' may have limited model support")
        else:
            self.logger.debug(f"Bedrock region '{bedrock_config.region}' is well-supported")
        
        # Validate model ID format
        if not bedrock_config.model or not isinstance(bedrock_config.model, str):
            errors.append({
                "error_type": "invalid_model",
                "message": "Model ID is required and must be a string",
                "suggestion": "Set a valid Bedrock model ID (e.g., 'anthropic.claude-3-sonnet-20240229-v1:0')"
            })
        elif not ('.' in bedrock_config.model and len(bedrock_config.model.split('.')) >= 2):
            errors.append({
                "error_type": "invalid_model_format",
                "message": f"Model ID '{bedrock_config.model}' does not follow expected format",
                "suggestion": "Use format 'provider.model-name' (e.g., 'anthropic.claude-3-sonnet-20240229-v1:0')"
            })
        else:
            self.logger.debug(f"Model ID '{bedrock_config.model}' format is valid")
        
        # Validate timeout
        if bedrock_config.timeout_seconds <= 0:
            errors.append({
                "error_type": "invalid_timeout",
                "message": f"Timeout must be positive, got {bedrock_config.timeout_seconds}",
                "suggestion": "Set timeout_seconds to a positive value (recommended: 300-600)"
            })
        elif bedrock_config.timeout_seconds < 30:
            warnings.append({
                "error_type": "low_timeout",
                "message": f"Timeout of {bedrock_config.timeout_seconds}s may be too low for complex requests",
                "suggestion": "Consider increasing timeout to at least 60 seconds"
            })
        elif bedrock_config.timeout_seconds > 900:
            warnings.append({
                "error_type": "high_timeout",
                "message": f"Timeout of {bedrock_config.timeout_seconds}s is very high",
                "suggestion": "Consider reducing timeout to avoid long waits on failures"
            })
        
        # Validate enhanced parameters
        if bedrock_config.temperature < 0.0 or bedrock_config.temperature > 1.0:
            errors.append({
                "error_type": "invalid_temperature",
                "message": f"Temperature must be between 0.0 and 1.0, got {bedrock_config.temperature}",
                "suggestion": "Set temperature to a value between 0.0 (deterministic) and 1.0 (creative)"
            })
        
        if bedrock_config.max_tokens <= 0:
            errors.append({
                "error_type": "invalid_max_tokens",
                "message": f"Max tokens must be positive, got {bedrock_config.max_tokens}",
                "suggestion": "Set max_tokens to a positive value (recommended: 1000-8000)"
            })
        elif bedrock_config.max_tokens > 100000:
            warnings.append({
                "error_type": "high_max_tokens",
                "message": f"Max tokens of {bedrock_config.max_tokens} is very high and may be expensive",
                "suggestion": "Consider reducing max_tokens unless you need very long responses"
            })
        
        if bedrock_config.top_p < 0.0 or bedrock_config.top_p > 1.0:
            errors.append({
                "error_type": "invalid_top_p",
                "message": f"Top-p must be between 0.0 and 1.0, got {bedrock_config.top_p}",
                "suggestion": "Set top_p to a value between 0.0 and 1.0 (recommended: 0.9-0.95)"
            })
        
        # Validate custom parameters
        if bedrock_config.custom_parameters:
            if not isinstance(bedrock_config.custom_parameters, dict):
                errors.append({
                    "error_type": "invalid_custom_parameters",
                    "message": "Custom parameters must be a dictionary",
                    "suggestion": "Provide custom parameters as a dictionary of key-value pairs"
                })
            else:
                self.logger.debug(f"Custom parameters validated: {len(bedrock_config.custom_parameters)} parameters")
        
        is_valid = len(errors) == 0
        
        self.logger.debug(f"Bedrock configuration validation completed: valid={is_valid}, "
                         f"errors={len(errors)}, warnings={len(warnings)}")
        
        return {
            "is_valid": is_valid,
            "errors": errors,
            "warnings": warnings
        }
    
    def _test_bedrock_connectivity(self, bedrock_config: BedrockConfig) -> Dict[str, Any]:
        """
        Test Bedrock connectivity using the existing BedrockClient.test_connection method.
        
        Args:
            bedrock_config: Bedrock configuration to test
            
        Returns:
            Dictionary with connectivity test result
        """
        self.logger.debug("Testing Bedrock connectivity")
        
        try:
            # Import BedrockClient here to avoid circular imports
            try:
                import importlib
                bedrock_module = importlib.import_module('threatforest.utils.bedrock_client')
                BedrockClient = bedrock_module.BedrockClient
                BedrockClientError = bedrock_module.BedrockClientError
            except ImportError as import_error:
                self.logger.warning(f"BedrockClient not available for connectivity test: {import_error}")
                return {
                    "is_valid": False,
                    "error_type": "import_error",
                    "message": "BedrockClient not available for connectivity test",
                    "suggestion": "This is expected during testing. BedrockClient will be available during normal operation."
                }
            
            # Create a BedrockClient instance
            client = BedrockClient(bedrock_config)
            
            # Use the existing test_connection method
            self.logger.debug("Calling BedrockClient.test_connection()")
            connection_successful = client.test_connection()
            
            if connection_successful:
                self.logger.info("Bedrock connectivity test successful")
                return {
                    "is_valid": True,
                    "message": "Bedrock connectivity test successful"
                }
            else:
                self.logger.warning("Bedrock connectivity test failed - unexpected response")
                return {
                    "is_valid": False,
                    "error_type": "connectivity_failed",
                    "message": "Bedrock connectivity test failed - model did not respond as expected",
                    "suggestion": "Check if the model is available in your region and your credentials have Bedrock permissions"
                }
        
        except Exception as e:
            # Check if it's a BedrockClientError by checking the class name
            if e.__class__.__name__ == 'BedrockClientError':
                self.logger.error(f"Bedrock client error during connectivity test: {e}")
                
                # Provide specific suggestions based on error type
                if hasattr(e, 'error_code'):
                    if e.error_code == 'AccessDeniedException':
                        suggestion = "Ensure your AWS credentials have bedrock:InvokeModel permissions"
                    elif e.error_code == 'ValidationException':
                        suggestion = "Check if the model ID is correct and available in your region"
                    elif e.error_code == 'ResourceNotFoundException':
                        suggestion = "The specified model may not be available in your region"
                    elif e.error_code == 'ThrottlingException':
                        suggestion = "Bedrock API is being throttled - try again later"
                    else:
                        suggestion = "Check your Bedrock configuration and AWS permissions"
                else:
                    suggestion = "Verify your Bedrock configuration and network connectivity"
                
                return {
                    "is_valid": False,
                    "error_type": "bedrock_client_error",
                    "message": f"Bedrock connectivity test failed: {e}",
                    "suggestion": suggestion
                }
            elif isinstance(e, ImportError):
                self.logger.error(f"Failed to import BedrockClient: {e}")
                return {
                    "is_valid": False,
                    "error_type": "import_error",
                    "message": "Failed to import BedrockClient for connectivity test",
                    "suggestion": "Ensure the BedrockClient module is available"
                }
            else:
                self.logger.error(f"Unexpected error during Bedrock connectivity test: {e}")
                return {
                    "is_valid": False,
                    "error_type": "unexpected_error",
                    "message": f"Unexpected error during connectivity test: {e}",
                    "suggestion": "Check your configuration and try again"
                }
    
    def _validate_other_config_sections(self, config: ThreatForestConfig) -> Dict[str, Any]:
        """
        Validate other configuration sections for common issues.
        
        Args:
            config: Configuration to validate
            
        Returns:
            Dictionary with validation results
        """
        self.logger.debug("Validating other configuration sections")
        
        warnings = []
        tested_components = {}
        
        # Validate output directory
        try:
            output_dir = Path(config.output.directory)
            if not output_dir.parent.exists():
                warnings.append({
                    "component": "output_config",
                    "error_type": "invalid_output_dir",
                    "message": f"Output directory parent does not exist: {output_dir.parent}",
                    "suggestion": "Ensure the parent directory exists or use a different output directory"
                })
            tested_components["output_config"] = True
            self.logger.debug(f"Output directory validation completed: {config.output.directory}")
        except Exception as e:
            self.logger.warning(f"Error validating output directory: {e}")
            tested_components["output_config"] = False
        
        # Validate TTC bundle path if specified
        try:
            if config.ttc.aaf_bundle_path and config.ttc.aaf_bundle_path != "./aaf-bundle.json":
                bundle_path = Path(config.ttc.aaf_bundle_path)
                if not bundle_path.exists():
                    warnings.append({
                        "component": "ttc_config",
                        "error_type": "missing_aaf_bundle",
                        "message": f"AAF bundle file not found: {bundle_path}",
                        "suggestion": "Ensure the AAF bundle file exists or use the default path"
                    })
            tested_components["ttc_config"] = True
            self.logger.debug("TTC configuration validation completed")
        except Exception as e:
            self.logger.warning(f"Error validating TTC configuration: {e}")
            tested_components["ttc_config"] = False
        
        # Validate processing configuration
        try:
            valid_severities = ["low", "medium", "high"]
            if config.processing.severity_threshold not in valid_severities:
                warnings.append({
                    "component": "processing_config",
                    "error_type": "invalid_severity",
                    "message": f"Invalid severity threshold: {config.processing.severity_threshold}",
                    "suggestion": f"Use one of: {', '.join(valid_severities)}"
                })
            
            if config.processing.max_concurrent_agents <= 0:
                warnings.append({
                    "component": "processing_config",
                    "error_type": "invalid_concurrency",
                    "message": f"Max concurrent agents must be positive: {config.processing.max_concurrent_agents}",
                    "suggestion": "Set max_concurrent_agents to a positive value (recommended: 2-8)"
                })
            
            tested_components["processing_config"] = True
            self.logger.debug("Processing configuration validation completed")
        except Exception as e:
            self.logger.warning(f"Error validating processing configuration: {e}")
            tested_components["processing_config"] = False
        
        return {
            "warnings": warnings,
            "tested_components": tested_components
        }