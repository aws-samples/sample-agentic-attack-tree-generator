"""
Configuration management for ThreatForest application.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field

from .exceptions import ConfigurationError
from .utils import get_logger


@dataclass
class LLMConfig:
    """Configuration for LLM providers."""
    provider: str = "bedrock"  # bedrock, openai, anthropic
    api_key: str = ""
    model: str = "anthropic.claude-3-sonnet-20240229-v1:0"
    max_tokens: int = 4000
    temperature: float = 0.1
    timeout: int = 60
    max_retries: int = 3
    # Bedrock-specific settings
    region: str = "us-east-1"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_session_token: str = ""


@dataclass
class STIXConfig:
    """Configuration for STIX processing."""
    bundle_path: str = "aaf-bundle.json"
    confidence_threshold: float = 0.8
    enable_mapping: bool = True


@dataclass
class OutputConfig:
    """Configuration for output generation."""
    include_timestamps: bool = True
    mermaid_theme: str = "default"
    generate_summary: bool = True


@dataclass
class ThreatForestConfig:
    """Main configuration class."""
    llm: LLMConfig = field(default_factory=LLMConfig)
    stix: STIXConfig = field(default_factory=STIXConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    additional_settings: Dict[str, Any] = field(default_factory=dict)


class ConfigManager:
    """Manages configuration loading and validation."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.logger = get_logger(__name__)
    
    def load_config(self) -> ThreatForestConfig:
        """
        Load configuration from file and environment variables.
        
        Returns:
            ThreatForestConfig object with loaded settings
        """
        config = ThreatForestConfig()
        
        # Load from file if provided
        if self.config_path:
            config = self._load_from_file(self.config_path, config)
        
        # Override with environment variables
        config = self._load_from_env(config)
        
        # Validate configuration
        self._validate_config(config)
        
        return config
    
    def _load_from_file(self, config_path: str, config: ThreatForestConfig) -> ThreatForestConfig:
        """Load configuration from YAML file."""
        try:
            path = Path(config_path)
            if not path.exists():
                raise ConfigurationError(f"Configuration file not found: {config_path}")
            
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
            
            if not data:
                self.logger.warning(f"Configuration file is empty: {config_path}")
                return config
            
            # Update LLM config
            if 'llm' in data:
                llm_data = data['llm']
                config.llm.provider = llm_data.get('provider', config.llm.provider)
                config.llm.api_key = llm_data.get('api_key', config.llm.api_key)
                config.llm.model = llm_data.get('model', config.llm.model)
                config.llm.max_tokens = llm_data.get('max_tokens', config.llm.max_tokens)
                config.llm.temperature = llm_data.get('temperature', config.llm.temperature)
                config.llm.timeout = llm_data.get('timeout', config.llm.timeout)
                config.llm.max_retries = llm_data.get('max_retries', config.llm.max_retries)
                config.llm.region = llm_data.get('region', config.llm.region)
                config.llm.aws_access_key_id = llm_data.get('aws_access_key_id', config.llm.aws_access_key_id)
                config.llm.aws_secret_access_key = llm_data.get('aws_secret_access_key', config.llm.aws_secret_access_key)
                config.llm.aws_session_token = llm_data.get('aws_session_token', config.llm.aws_session_token)
            
            # Update STIX config
            if 'stix' in data:
                stix_data = data['stix']
                config.stix.bundle_path = stix_data.get('bundle_path', config.stix.bundle_path)
                config.stix.confidence_threshold = stix_data.get('confidence_threshold', config.stix.confidence_threshold)
                config.stix.enable_mapping = stix_data.get('enable_mapping', config.stix.enable_mapping)
            
            # Update output config
            if 'output' in data:
                output_data = data['output']
                config.output.include_timestamps = output_data.get('include_timestamps', config.output.include_timestamps)
                config.output.mermaid_theme = output_data.get('mermaid_theme', config.output.mermaid_theme)
                config.output.generate_summary = output_data.get('generate_summary', config.output.generate_summary)
            
            # Store additional settings
            config.additional_settings = {k: v for k, v in data.items() 
                                        if k not in ['llm', 'stix', 'output']}
            
            self.logger.info(f"Configuration loaded from: {config_path}")
            
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in configuration file: {e}")
        except Exception as e:
            raise ConfigurationError(f"Error loading configuration file: {e}")
        
        return config
    
    def _load_from_env(self, config: ThreatForestConfig) -> ThreatForestConfig:
        """Load configuration from environment variables."""
        # LLM configuration - prioritize Bedrock, then others
        if os.getenv('AWS_ACCESS_KEY_ID') or os.getenv('AWS_PROFILE'):
            config.llm.provider = 'bedrock'
            config.llm.aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID', '')
            config.llm.aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY', '')
            config.llm.aws_session_token = os.getenv('AWS_SESSION_TOKEN', '')
            config.llm.region = os.getenv('AWS_DEFAULT_REGION', config.llm.region)
        elif os.getenv('OPENAI_API_KEY'):
            config.llm.api_key = os.getenv('OPENAI_API_KEY')
            config.llm.provider = 'openai'
        elif os.getenv('ANTHROPIC_API_KEY'):
            config.llm.api_key = os.getenv('ANTHROPIC_API_KEY')
            config.llm.provider = 'anthropic'
        
        # Override specific settings from environment
        if os.getenv('TF_LLM_MODEL'):
            config.llm.model = os.getenv('TF_LLM_MODEL')
        
        if os.getenv('TF_LLM_PROVIDER'):
            config.llm.provider = os.getenv('TF_LLM_PROVIDER')
        
        if os.getenv('TF_AWS_REGION'):
            config.llm.region = os.getenv('TF_AWS_REGION')
        
        if os.getenv('TF_STIX_BUNDLE_PATH'):
            config.stix.bundle_path = os.getenv('TF_STIX_BUNDLE_PATH')
        
        if os.getenv('TF_CONFIDENCE_THRESHOLD'):
            try:
                config.stix.confidence_threshold = float(os.getenv('TF_CONFIDENCE_THRESHOLD'))
            except ValueError:
                self.logger.warning("Invalid TF_CONFIDENCE_THRESHOLD value, using default")
        
        return config
    
    def _validate_config(self, config: ThreatForestConfig) -> None:
        """Validate configuration settings."""
        # Validate LLM configuration
        if config.llm.provider == 'bedrock':
            # For Bedrock, we don't need API key but need AWS credentials or profile
            if not (config.llm.aws_access_key_id or os.getenv('AWS_PROFILE') or os.getenv('AWS_ACCESS_KEY_ID')):
                raise ConfigurationError(
                    "AWS credentials are required for Bedrock. Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY "
                    "environment variables, configure AWS_PROFILE, or provide credentials in config file."
                )
        elif config.llm.provider in ['openai', 'anthropic']:
            if not config.llm.api_key:
                raise ConfigurationError(
                    f"API key is required for {config.llm.provider}. Set the appropriate environment variable "
                    "or provide it in the configuration file."
                )
        else:
            raise ConfigurationError(f"Unsupported LLM provider: {config.llm.provider}")
        
        if config.llm.temperature < 0 or config.llm.temperature > 1:
            raise ConfigurationError("LLM temperature must be between 0 and 1")
        
        if config.llm.max_tokens < 1:
            raise ConfigurationError("LLM max_tokens must be positive")
        
        # Validate STIX configuration
        if config.stix.confidence_threshold < 0 or config.stix.confidence_threshold > 1:
            raise ConfigurationError("STIX confidence threshold must be between 0 and 1")
        
        self.logger.info("Configuration validation passed")
    
    def save_config(self, config: ThreatForestConfig, output_path: str) -> None:
        """Save configuration to file for reference."""
        try:
            config_dict = {
                'llm': {
                    'provider': config.llm.provider,
                    'model': config.llm.model,
                    'max_tokens': config.llm.max_tokens,
                    'temperature': config.llm.temperature,
                    'timeout': config.llm.timeout,
                    'max_retries': config.llm.max_retries,
                    'region': config.llm.region
                },
                'stix': {
                    'bundle_path': config.stix.bundle_path,
                    'confidence_threshold': config.stix.confidence_threshold,
                    'enable_mapping': config.stix.enable_mapping
                },
                'output': {
                    'include_timestamps': config.output.include_timestamps,
                    'mermaid_theme': config.output.mermaid_theme,
                    'generate_summary': config.output.generate_summary
                }
            }
            
            # Add additional settings
            config_dict.update(config.additional_settings)
            
            with open(output_path, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            
            self.logger.info(f"Configuration saved to: {output_path}")
            
        except Exception as e:
            self.logger.warning(f"Failed to save configuration: {e}")