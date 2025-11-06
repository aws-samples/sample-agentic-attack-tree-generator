"""Bedrock service with rate limiting"""
import json
from typing import Optional, Dict, Any
from .bedrock_client import BedrockClientManager
from .rate_limiter import BedrockRateLimiter


class BedrockService:
    """Service for making Bedrock API calls with rate limiting"""
    
    def __init__(
        self,
        profile_name: Optional[str] = None,
        region_name: Optional[str] = None
    ):
        self.client_manager = BedrockClientManager()
        self.client = self.client_manager.get_client(profile_name, region_name)
        self.rate_limiter = BedrockRateLimiter()
    
    async def invoke_model(
        self,
        model_id: str,
        prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        """Invoke Bedrock model with rate limiting"""
        
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
        
        return content
