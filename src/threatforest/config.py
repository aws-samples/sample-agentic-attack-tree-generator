"""Configuration loader for ThreatForest"""

import os
from pathlib import Path
from typing import Any, Dict

import yaml
from dotenv import load_dotenv

from threatforest.frameworks import FRAMEWORKS

# Root directory of the ThreatForest project - use __file__ path, not cwd
# This gives us the repo root: /path/to/ThreatForest-internal
ROOT_DIR = Path(__file__).parent.parent.parent

# Load environment variables — check cwd first, then ROOT_DIR
_cwd_env = Path.cwd() / ".threatforest" / ".env"
ENV_FILE = _cwd_env if _cwd_env.is_file() else ROOT_DIR / ".threatforest" / ".env"
ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
load_dotenv(dotenv_path=ENV_FILE, override=True)


class Config:
    """Configuration manager for ThreatForest"""

    _instance = None
    _config = None
    _config_path = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        # Don't load config at init - do it lazily when first accessed
        pass

    def _find_config_file(self) -> Path:
        """Find config.yaml using a search hierarchy.

        Resolution order:
        1. cwd/.threatforest/config.yaml  — workspace config (UI / user runs from repo root)
        2. ROOT_DIR/.threatforest/config.yaml — relative to engine source (editable installs)

        This ensures the config is found regardless of install method
        (uv tool, pipx, pip, editable, PYTHONPATH).
        """
        candidates = [
            Path.cwd() / ".threatforest" / "config.yaml",
            ROOT_DIR / ".threatforest" / "config.yaml",
        ]
        for candidate in candidates:
            if candidate.is_file():
                return candidate

        raise FileNotFoundError(
            f"Configuration file not found. Searched:\n"
            f"  1. {candidates[0]}\n"
            f"  2. {candidates[1]}\n"
            "\nTo fix: Run 'threatforest' to auto-create config or "
            "save configuration via the Configure page."
        )

    def _load_config(self):
        """Load configuration from config.yaml (lazy loading)"""
        if self._config is not None:
            return  # Already loaded
            
        self._config_path = self._find_config_file()

        with open(self._config_path, "r") as f:
            self._config = yaml.safe_load(f)

    def reset(self):
        """Clear cached config so it reloads from disk on next access.

        Called by the web console after saving configuration so the next
        pipeline run picks up the updated config.yaml.
        """
        self._config = None
        self._config_path = None

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-notation key (e.g., 'data.stix_bundle')"""
        # Lazy load config on first access
        if self._config is None:
            self._load_config()
            
        keys = key.split(".")
        value = self._config

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default

        return value if value is not None else default

    @property
    def frameworks(self) -> Dict[str, Dict[str, Any]]:
        """Get all available framework definitions.

        Always returns the canonical set from ``threatforest.frameworks``.
        User config may override individual framework settings, but the
        registry in ``frameworks.py`` is the source of truth for which
        frameworks exist.
        """
        return dict(FRAMEWORKS)

    @property
    def stix_bundle_path(self) -> Path:
        """Get absolute path to STIX bundle file (default ATT&CK — kept for backward compat)."""
        return (
            Path(__file__).parent / "data" / "threat-intelligence" / "enterprise-attack-18.0.json"
        )

    def stix_bundle_path_for(self, framework_key: str) -> Path:
        """Get absolute path to the STIX bundle for a specific framework."""
        fw = self.frameworks.get(framework_key, {})
        bundle_name = fw.get("stix_bundle", "enterprise-attack-18.0.json")
        return Path(__file__).parent / "data" / "threat-intelligence" / bundle_name

    @property
    def embeddings_model(self) -> str:
        """Get embeddings model name"""
        return self.get("embeddings.model", "basel/ATTACK-BERT")

    @property
    def graph_file_path(self) -> Path:
        """Get absolute path to graph file in .threatforest/ directory (default ATT&CK)."""
        return self.graph_file_path_for("attack")

    def graph_file_path_for(self, framework_key: str) -> Path:
        """Get absolute path to graph cache file for a specific framework."""
        graph_dir = ROOT_DIR / ".threatforest" / "graphs"
        graph_dir.mkdir(parents=True, exist_ok=True)
        model_name = self.embeddings_model.replace("/", "_").replace("\\", "_")
        return graph_dir / f"{framework_key}_graph_{model_name}.json"

    @property
    def ttc_threshold(self) -> float:
        """Get TTC matching similarity threshold"""
        return self.get("embeddings.ttc_threshold", 0.3)

    @property
    def parallel_max_retries(self) -> int:
        """Max retry rounds for failed threats in the parallel pipeline.

        A value of 1 means 1 retry after the initial run (2 total attempts).
        Set to 0 to disable retries.
        """
        return int(self.get("parallel.max_retries", 1))

    # Model provider configurations
    @property
    def bedrock(self) -> Dict[str, Any]:
        """Get Bedrock configuration"""
        return self.get("bedrock", {})

    @property
    def anthropic(self) -> Dict[str, Any]:
        """Get Anthropic configuration"""
        return self.get("anthropic", {})

    @property
    def openai(self) -> Dict[str, Any]:
        """Get OpenAI configuration"""
        return self.get("openai", {})

    @property
    def gemini(self) -> Dict[str, Any]:
        """Get Gemini configuration"""
        return self.get("gemini", {})

    @property
    def litellm(self) -> Dict[str, Any]:
        """Get LiteLLM configuration"""
        return self.get("litellm", {})

    @property
    def llamaapi(self) -> Dict[str, Any]:
        """Get LlamaAPI configuration"""
        return self.get("llamaapi", {})

    @property
    def ollama(self) -> Dict[str, Any]:
        """Get Ollama configuration"""
        return self.get("ollama", {})

    # Legacy AWS settings (kept for backward compatibility)
    @property
    def default_aws_profile(self) -> str:
        """Get default AWS profile - reads from .env first, then config.yaml"""
        return os.getenv("AWS_PROFILE") or self.get("aws.default_profile", "default")

    @property
    def default_aws_region(self) -> str:
        """Get default AWS region - reads from .env first, then config.yaml"""
        return os.getenv("AWS_REGION") or self.get("aws.default_region", "us-east-1")

    # Helper properties for display/logging
    @property
    def default_bedrock_model(self) -> str:
        """Get active model ID (for display purposes)"""
        # Return model_id from whichever provider is configured
        for provider in [
            "bedrock",
            "anthropic",
            "openai",
            "gemini",
            "ollama",
            "litellm",
            "llamaapi",
        ]:
            provider_config = getattr(self, provider, {})
            if provider_config:
                return provider_config.get("model_id", f"{provider} (configured)")
        return "No model configured"


# Singleton instance
config = Config()
