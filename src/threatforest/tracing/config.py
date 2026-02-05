"""
Langfuse Configuration Module

This module provides configuration management for Langfuse tracing integration.
Configuration can be loaded from environment variables or config.yaml file.

Requirements:
- 1.1: Support Langfuse settings including public_key, secret_key, host, and enabled flag
- 1.3: Raise descriptive error when enabled but credentials missing
- 1.4: Support loading from environment variables with LANGFUSE_ prefix
- 1.5: Support loading from config.yaml file
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional, TYPE_CHECKING
import os

if TYPE_CHECKING:
    from threatforest.config import Config


@dataclass
class LangfuseConfig:
    """
    Configuration for Langfuse connection.
    
    This dataclass holds all configuration needed to connect to Langfuse
    for tracing ThreatForest workflows. It supports loading from environment
    variables or from a config.yaml file.
    
    Attributes:
        enabled: Whether Langfuse tracing is enabled. Defaults to False.
        public_key: Langfuse public API key for authentication.
        secret_key: Langfuse secret API key for authentication.
        host: Langfuse server host URL. Defaults to cloud.langfuse.com.
    
    Example:
        >>> # Load from environment variables
        >>> config = LangfuseConfig.from_env()
        >>> config.validate()  # Raises ValueError if enabled but credentials missing
        
        >>> # Load from config file
        >>> from threatforest.config import Config
        >>> app_config = Config()
        >>> config = LangfuseConfig.from_config_file(app_config)
    """
    
    enabled: bool = False
    public_key: Optional[str] = None
    secret_key: Optional[str] = None
    host: str = "https://cloud.langfuse.com"
    
    @classmethod
    def from_env(cls) -> "LangfuseConfig":
        """
        Load configuration from environment variables.
        
        Environment variables:
            - LANGFUSE_ENABLED: "true" or "false" (case-insensitive)
            - LANGFUSE_PUBLIC_KEY: Public API key
            - LANGFUSE_SECRET_KEY: Secret API key
            - LANGFUSE_HOST: Server host URL (optional, defaults to cloud.langfuse.com)
        
        Returns:
            LangfuseConfig: Configuration loaded from environment variables.
        
        Example:
            >>> import os
            >>> os.environ["LANGFUSE_ENABLED"] = "true"
            >>> os.environ["LANGFUSE_PUBLIC_KEY"] = "pk-lf-xxx"
            >>> os.environ["LANGFUSE_SECRET_KEY"] = "sk-lf-xxx"
            >>> config = LangfuseConfig.from_env()
            >>> config.enabled
            True
        """
        enabled = os.getenv("LANGFUSE_ENABLED", "false").lower() == "true"
        return cls(
            enabled=enabled,
            public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
            secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
            host=os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com")
        )
    
    @classmethod
    def from_config_file(cls, config: "Config") -> "LangfuseConfig":
        """
        Load configuration from config.yaml via the Config object.
        
        The config.yaml should have a 'langfuse' section with the following keys:
            - enabled: boolean
            - public_key: string
            - secret_key: string
            - host: string (optional)
        
        Args:
            config: ThreatForest Config object that provides access to config.yaml.
        
        Returns:
            LangfuseConfig: Configuration loaded from config file.
        
        Example:
            >>> from threatforest.config import Config
            >>> app_config = Config()
            >>> langfuse_config = LangfuseConfig.from_config_file(app_config)
        
        Note:
            If the 'langfuse' section is missing from config.yaml, default values
            will be used (enabled=False, host=cloud.langfuse.com).
        """
        langfuse_config: Dict[str, Any] = config.get("langfuse", {}) or {}
        return cls(
            enabled=langfuse_config.get("enabled", False),
            public_key=langfuse_config.get("public_key"),
            secret_key=langfuse_config.get("secret_key"),
            host=langfuse_config.get("host", "https://cloud.langfuse.com")
        )
    
    def validate(self) -> None:
        """
        Validate the configuration and raise an error if invalid.
        
        This method checks that when Langfuse is enabled, both public_key
        and secret_key are provided. This validation should be called at
        startup to fail fast with a descriptive error message.
        
        Raises:
            ValueError: If enabled is True but public_key or secret_key is missing.
        
        Example:
            >>> config = LangfuseConfig(enabled=True, public_key=None, secret_key=None)
            >>> config.validate()
            Traceback (most recent call last):
                ...
            ValueError: Langfuse is enabled but credentials are missing. ...
        """
        if self.enabled and (not self.public_key or not self.secret_key):
            raise ValueError(
                "Langfuse is enabled but credentials are missing. "
                "Set LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY environment variables."
            )
