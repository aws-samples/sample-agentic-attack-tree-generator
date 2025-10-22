"""
Centralized Bedrock invocation with retry logic and error handling
"""
import json
import asyncio
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError
from .bedrock_client import BedrockClientManager
from ..utils.logger import ThreatForestLogger


class BedrockInvoker:
    """Centralized Bedrock invocation with retry logic and error handling"""
    
    def __init__(self, rate_limit_delay: float = 2.5, max_retries: int = 3, base_backoff: float = 2.0):
        self.rate_limit_delay = rate_limit_delay
        self.max_retries = max_retries
        self.base_backoff = base_backoff
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
    
    async def invoke_with_retry(
        self,
        model_id: str,
        prompt: str,
        aws_profile: Optional[str] = None,
        max_tokens: int = 65536,
        temperature: float = 0.7,
        system_prompt: str = ""
    ) -> str:
        """
        Invoke Bedrock with automatic retry and error handling
        
        Args:
            model_id: Bedrock model ID or ARN
            prompt: User prompt text
            aws_profile: AWS profile name
            max_tokens: Maximum tokens in response
            temperature: Model temperature
            system_prompt: Optional system prompt
            
        Returns:
            Generated text content
            
        Raises:
            Exception: After max retries or on non-retryable errors
        """
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                return await self._invoke_bedrock(
                    model_id, prompt, aws_profile, max_tokens, temperature, system_prompt
                )
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                error_msg = e.response.get('Error', {}).get('Message', str(e))
                
                if error_code == 'ThrottlingException':
                    wait_time = self.base_backoff * (2 ** attempt)
                    self.logger.warning(f"Throttled (attempt {attempt + 1}/{self.max_retries}), waiting {wait_time}s")
                    
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(wait_time)
                        continue
                    else:
                        raise Exception(f"Throttling error after {self.max_retries} retries: {error_msg}")
                else:
                    self.logger.error(f"Bedrock API error: {error_code} - {error_msg}")
                    raise Exception(f"Bedrock API error ({error_code}): {error_msg}")
                    
            except Exception as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    wait_time = self.base_backoff * (2 ** attempt)
                    self.logger.warning(f"Attempt {attempt + 1} failed, retrying in {wait_time}s: {str(e)}")
                    await asyncio.sleep(wait_time)
                else:
                    self.logger.error(f"All retry attempts failed: {str(e)}")
                    raise
        
        raise last_error if last_error else Exception("Unknown error in retry logic")
    
    async def _invoke_bedrock(
        self,
        model_id: str,
        prompt: str,
        aws_profile: Optional[str],
        max_tokens: int,
        temperature: float,
        system_prompt: str
    ) -> str:
        """Internal method to invoke Bedrock"""
        bedrock = BedrockClientManager().get_client(profile_name=aws_profile)
        
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}]
        }
        
        if system_prompt:
            body["system"] = system_prompt
        
        if temperature != 0.7:
            body["temperature"] = temperature
        
        # Convert cross-region inference profile IDs to ARNs (use default region from client)
        if model_id.startswith('us.') or model_id.startswith('eu.'):
            # Get region from bedrock client
            region = bedrock.meta.region_name
            model_id = f"arn:aws:bedrock:{region}::foundation-model/{model_id}"
        
        response = bedrock.invoke_model(
            modelId=model_id,
            body=json.dumps(body)
        )
        
        response_body = json.loads(response['body'].read())
        return response_body['content'][0]['text']
