"""Bedrock service with integrated caching and rate limiting"""
import json
import hashlib
from typing import Optional, Dict, Any
from .bedrock_client import BedrockClientManager
from .cache import BedrockResponseCache
from .rate_limiter import BedrockRateLimiter


class BedrockService:
    """Service for making Bedrock API calls with caching and rate limiting"""
    
    def __init__(
        self,
        profile_name: Optional[str] = None,
        region_name: str = "us-west-2",
        enable_cache: bool = True
    ):
        self.client_manager = BedrockClientManager()
        self.client = self.client_manager.get_client(profile_name, region_name)
        self.rate_limiter = BedrockRateLimiter()
        self.cache = BedrockResponseCache() if enable_cache else None
        self.enable_cache = enable_cache
    
    async def invoke_model(
        self,
        model_id: str,
        prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        """Invoke Bedrock model with caching and rate limiting"""
        
        # Check cache first
        if self.enable_cache and self.cache:
            cache_key = self._generate_cache_key(model_id, prompt, max_tokens, temperature)
            cached_response = self.cache.get(cache_key)
            if cached_response:
                return cached_response
        
        # Apply rate limiting
        await self.rate_limiter.acquire()
        
        # Prepare request body
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}]
        }
        body.update(kwargs)
        
        # Make API call
        response = self.client.invoke_model(
            modelId=model_id,
            body=json.dumps(body)
        )
        
        # Parse response
        response_body = json.loads(response['body'].read())
        content = response_body['content'][0]['text']
        
        # Cache response
        if self.enable_cache and self.cache:
            self.cache.set(cache_key, content)
        
        return content
    
    def _generate_cache_key(
        self,
        model_id: str,
        prompt: str,
        max_tokens: int,
        temperature: float
    ) -> str:
        """Generate cache key from request parameters"""
        key_data = f"{model_id}:{prompt}:{max_tokens}:{temperature}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def get_cache_stats(self) -> Optional[Dict[str, Any]]:
        """Get cache statistics"""
        if self.cache:
            return self.cache.get_stats()
        return None
    
    def clear_cache(self):
        """Clear the response cache"""
        if self.cache:
            self.cache.clear()
