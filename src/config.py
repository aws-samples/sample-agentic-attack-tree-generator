"""Configuration loader for ThreatForest"""
import yaml
from pathlib import Path
from typing import Dict, Any

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
        """Get absolute path to STIX bundle file"""
        base_path = Path(__file__).parent.parent
        return base_path / self.get('data.stix_bundle', 'data/aaf-bundle.json')
    
    @property
    def embeddings_file_path(self) -> Path:
        """Get absolute path to embeddings file"""
        base_path = Path(__file__).parent.parent
        return base_path / self.get('data.embeddings_file', 'data/embeddings/attack_pattern_embeddings_qwen.json')
    
    @property
    def output_dir(self) -> str:
        """Get output directory"""
        return self.get('data.output_dir', 'output')
    
    @property
    def input_dir(self) -> str:
        """Get input directory"""
        return self.get('data.input_dir', '')
    
    @property
    def embeddings_model(self) -> str:
        """Get embeddings model name"""
        return self.get('embeddings.model', 'cisco-ai/SecureBERT2.0-base')
    
    @property
    def embeddings_mode(self) -> str:
        """Get embeddings mode (local or neptune)"""
        return self.get('embeddings.mode', 'local')
    
    @property
    def neptune_graph_id(self) -> str:
        """Get Neptune graph ID"""
        return self.get('neptune.graph_id', '')
    
    @property
    def neptune_region(self) -> str:
        """Get Neptune region"""
        return self.get('neptune.region', 'us-east-1')
    
    @property
    def neptune_s3_bucket(self) -> str:
        """Get Neptune S3 bucket"""
        return self.get('neptune.s3_bucket', '')
    
    @property
    def neptune_account_id(self) -> str:
        """Get Neptune account ID"""
        return self.get('neptune.account_id', '')
    
    @property
    def default_bedrock_model(self) -> str:
        """Get default Bedrock model"""
        return self.get('models.default_bedrock_model', '')
    
    @property
    def default_aws_profile(self) -> str:
        """Get default AWS profile"""
        return self.get('aws.default_profile', 'default')
    
    @property
    def default_aws_region(self) -> str:
        """Get default AWS region"""
        return self.get('aws.default_region', 'us-east-1')

# Singleton instance
config = Config()
