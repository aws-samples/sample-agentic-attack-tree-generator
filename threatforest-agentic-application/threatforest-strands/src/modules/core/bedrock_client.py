"""Bedrock client manager with connection pooling and reuse"""
import boto3
from typing import Optional, Dict
from botocore.config import Config


class BedrockClientManager:
    """Singleton manager for AWS Bedrock clients with connection pooling"""
    
    _instance = None
    _clients: Dict[str, any] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._initialized = True
            self._clients = {}
    
    def get_client(
        self,
        profile_name: Optional[str] = None,
        region_name: Optional[str] = None
    ):
        """Get or create a Bedrock client with connection pooling"""
        # Use default region from AWS config if not specified
        if region_name is None:
            import boto3
            session = boto3.Session(profile_name=profile_name) if profile_name else boto3.Session()
            region_name = session.region_name or "us-west-2"
        
        # Create cache key
        cache_key = f"{profile_name or 'default'}:{region_name}"
        
        # Return cached client if exists
        if cache_key in self._clients:
            return self._clients[cache_key]
        
        # Configure client with connection pooling and retries
        config = Config(
            max_pool_connections=50,
            retries={
                'mode': 'adaptive',
                'max_attempts': 3
            },
            connect_timeout=10,
            read_timeout=60
        )
        
        # Create session
        if profile_name:
            session = boto3.Session(profile_name=profile_name)
        else:
            session = boto3.Session()
        
        # Create and cache client
        client = session.client(
            'bedrock-runtime',
            region_name=region_name,
            config=config
        )
        
        self._clients[cache_key] = client
        return client
    
    def clear_cache(self):
        """Clear all cached clients"""
        self._clients.clear()
    
    def get_active_connections(self) -> int:
        """Get count of active client connections"""
        return len(self._clients)
