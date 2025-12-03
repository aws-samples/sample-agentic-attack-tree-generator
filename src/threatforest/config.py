"""Configuration loader for ThreatForest"""
import yaml
from pathlib import Path
from typing import Dict, Any
import os
from dotenv import load_dotenv


# Root directory of the ThreatForest project - use __file__ path, not cwd
# This gives us the repo root: /path/to/ThreatForest-internal
ROOT_DIR = Path(__file__).parent.parent.parent

# Load environment variables from fixed location in .threatforest/.env
ENV_FILE = ROOT_DIR / ".threatforest" / ".env"
ENV_FILE.parent.mkdir(parents=True, exist_ok=True)  # Ensure directory exists
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
        if self._config is None:
            self._load_config()
    
    def _find_config_file(self) -> Path:
        """Find config.yaml using professional search hierarchy"""
        # Priority 1: Project config directory
        project_config = Path.cwd() / ".threatforest" / "config.yaml"
        if project_config.exists():
            return project_config
        
        # Priority 2: Current directory (root override)
        current_dir_config = Path.cwd() / "config.yaml"
        if current_dir_config.exists():
            return current_dir_config
        
        # Priority 3: Bundled default in package
        bundled_config = Path(__file__).parent / "config.yaml"
        if bundled_config.exists():
            return bundled_config
        
        raise FileNotFoundError(
            "Configuration file not found. Checked:\n"
            f"  1. {project_config} (project config)\n"
            f"  2. {current_dir_config} (root override)\n"
            f"  3. {bundled_config} (bundled default)\n"
            "\nTo fix: Run 'threatforest' to auto-create config or copy config.yaml to one of these locations."
        )
    
    def _load_config(self):
        """Load configuration from config.yaml"""
        self._config_path = self._find_config_file()
        
        with open(self._config_path, 'r') as f:
            self._config = yaml.safe_load(f)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-notation key (e.g., 'data.stix_bundle')"""
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        
        return value if value is not None else default
    
    @property
    def stix_bundle_path(self) -> Path:
        """Get absolute path to STIX bundle file"""
        # Try current directory first, then packaged data
        current_path = Path.cwd() / "data" / "threat-intelligence" / "enterprise-attack-18.0.json"
        if current_path.exists():
            return current_path
        
        # Use bundled data in package
        return Path(__file__).parent / "data" / "threat-intelligence" / "enterprise-attack-18.0.json"
    
    @property
    def embeddings_model(self) -> str:
        """Get embeddings model name"""
        return self.get('embeddings.model', 'basel/ATTACK-BERT')
    
    @property
    def graph_file_path(self) -> Path:
        """Get absolute path to graph file in .threatforest/ directory"""
        # Use .threatforest/graphs/ for user-generated graph cache
        # This allows per-user, per-embedding-model graphs
        graph_dir = Path.cwd() / ".threatforest" / "graphs"
        graph_dir.mkdir(parents=True, exist_ok=True)
        
        # Use embedding model name in filename for versioning
        # Sanitize model name for filesystem
        model_name = self.embeddings_model.replace('/', '_').replace('\\', '_')
        graph_file = graph_dir / f"mitre_attack_graph_{model_name}.json"
        
        return graph_file
    
    @property
    def ttc_threshold(self) -> float:
        """Get TTC matching similarity threshold"""
        return self.get('embeddings.ttc_threshold', 0.3)
    
    # Model provider configurations
    @property
    def bedrock(self) -> Dict[str, Any]:
        """Get Bedrock configuration"""
        return self.get('bedrock', {})
    
    @property
    def anthropic(self) -> Dict[str, Any]:
        """Get Anthropic configuration"""
        return self.get('anthropic', {})
    
    @property
    def openai(self) -> Dict[str, Any]:
        """Get OpenAI configuration"""
        return self.get('openai', {})
    
    @property
    def gemini(self) -> Dict[str, Any]:
        """Get Gemini configuration"""
        return self.get('gemini', {})
    
    @property
    def litellm(self) -> Dict[str, Any]:
        """Get LiteLLM configuration"""
        return self.get('litellm', {})
    
    @property
    def llamaapi(self) -> Dict[str, Any]:
        """Get LlamaAPI configuration"""
        return self.get('llamaapi', {})
    
    @property
    def ollama(self) -> Dict[str, Any]:
        """Get Ollama configuration"""
        return self.get('ollama', {})
    
    # Legacy AWS settings (kept for backward compatibility)
    @property
    def default_aws_profile(self) -> str:
        """Get default AWS profile - reads from .env first, then config.yaml"""
        return os.getenv('AWS_PROFILE') or self.get('aws.default_profile', 'default')
    
    @property
    def default_aws_region(self) -> str:
        """Get default AWS region - reads from .env first, then config.yaml"""
        return os.getenv('AWS_REGION') or self.get('aws.default_region', 'us-east-1')
    
    # Helper properties for display/logging
    @property
    def default_bedrock_model(self) -> str:
        """Get active model ID (for display purposes)"""
        # Return model_id from whichever provider is configured
        for provider in ['bedrock', 'anthropic', 'openai', 'gemini', 'ollama', 'litellm', 'llamaapi']:
            provider_config = getattr(self, provider, {})
            if provider_config:
                return provider_config.get('model_id', f'{provider} (configured)')
        return 'No model configured'

# Singleton instance
config = Config()
