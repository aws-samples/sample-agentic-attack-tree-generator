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
from pathlib import Path
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field


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
        # Start with default configuration
        config_data = {}
        
        # Load user-level config file
        user_config = self._load_user_config()
        if user_config:
            config_data.update(user_config)
        
        # Load project-level config file
        project_config = self._load_project_config(config_file)
        if project_config:
            config_data.update(project_config)
        
        # Load environment variables
        env_config = self._load_env_config()
        config_data.update(env_config)
        
        # Apply CLI arguments (highest priority)
        if cli_args:
            config_data.update(cli_args)
        
        # Create and cache configuration
        self._config = ThreatForestConfig(**config_data)
        return self._config
    
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
            return None
        
        try:
            with open(file_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except (yaml.YAMLError, IOError) as e:
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
        
        # Create directory if it doesn't exist
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert config to dictionary and save as YAML
        config_dict = config.model_dump()
        
        try:
            with open(config_path, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
        except IOError as e:
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