"""Configuration loader for ThreatForest"""
import yaml
from pathlib import Path
from typing import Dict, Any

# Root directory of the ThreatForest project
ROOT_DIR = Path(__file__).parent.parent

class Config:
    """Configuration manager for ThreatForest"""
    
    _instance = None
    _config = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._config is None:
            self._load_config()
    
    def _load_config(self):
        """Load configuration from config.yaml"""
        config_path = Path(__file__).parent.parent / "config.yaml"
        
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_path, 'r') as f:
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
        """Get absolute path to STIX bundle file (hardcoded internal path)"""
        return ROOT_DIR / "data/threat-intelligence/enterprise-attack-18.0.json"
    
    @property
    def embeddings_model(self) -> str:
        """Get embeddings model name"""
        return self.get('embeddings.model', 'cisco-ai/SecureBERT2.0-biencoder')
    
    @property
    def graph_file_path(self) -> Path:
        """Get absolute path to graph file"""
        return ROOT_DIR / self.get('embeddings.graph_file', 'data/graphs/mitre_attack_graph.json')
    
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
    
    @property
    def sagemaker(self) -> Dict[str, Any]:
        """Get SageMaker configuration"""
        return self.get('sagemaker', {})
    
    # Legacy AWS settings (kept for backward compatibility)
    @property
    def default_aws_profile(self) -> str:
        """Get default AWS profile"""
        return self.get('aws.default_profile', 'default')
    
    @property
    def default_aws_region(self) -> str:
        """Get default AWS region"""
        return self.get('aws.default_region', 'us-east-1')
    
    # Helper properties for display/logging
    @property
    def default_bedrock_model(self) -> str:
        """Get active model ID (for display purposes)"""
        # Return model_id from whichever provider is configured
        for provider in ['bedrock', 'anthropic', 'openai', 'gemini', 'ollama', 'litellm', 'llamaapi', 'sagemaker']:
            provider_config = getattr(self, provider, {})
            if provider_config:
                return provider_config.get('model_id', f'{provider} (configured)')
        return 'No model configured'

# Singleton instance
config = Config()
