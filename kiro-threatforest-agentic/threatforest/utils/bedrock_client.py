"""
Amazon Bedrock client integration for ThreatForest.

This module provides a wrapper around the Bedrock API for AI model interactions,
including authentication, error handling, and retry logic.
"""

import json
import time
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from botocore.config import Config

from ..config import BedrockConfig


logger = logging.getLogger(__name__)


@dataclass
class BedrockResponse:
    """Response from Bedrock API call."""
    
    content: str
    model_id: str
    input_tokens: int
    output_tokens: int
    stop_reason: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class BedrockClientError(Exception):
    """Custom exception for Bedrock client errors."""
    
    def __init__(self, message: str, error_code: Optional[str] = None, retry_after: Optional[int] = None):
        super().__init__(message)
        self.error_code = error_code
        self.retry_after = retry_after


class BedrockClient:
    """
    Wrapper client for Amazon Bedrock API interactions.
    
    Provides authentication, error handling, retry logic, and model abstraction
    for AI-powered threat analysis operations.
    """
    
    def __init__(self, config: BedrockConfig):
        """
        Initialize Bedrock client.
        
        Args:
            config: Bedrock configuration settings
        """
        self.config = config
        self._client = None
        self._session = None
        
        # Retry configuration
        self.max_retries = 3
        self.base_delay = 1.0
        self.max_delay = 60.0
        
        # Initialize client
        self._initialize_client()
    
    def _initialize_client(self) -> None:
        """Initialize the Bedrock client with proper configuration."""
        try:
            # Create boto3 session
            self._session = boto3.Session()
            
            # Configure client with retry settings
            client_config = Config(
                region_name=self.config.region,
                retries={
                    'max_attempts': self.max_retries,
                    'mode': 'adaptive'
                },
                read_timeout=self.config.timeout_seconds,
                connect_timeout=30
            )
            
            # Create Bedrock runtime client
            self._client = self._session.client(
                'bedrock-runtime',
                config=client_config
            )
            
            logger.info(f"Bedrock client initialized for region: {self.config.region}")
            
        except Exception as e:
            raise BedrockClientError(f"Failed to initialize Bedrock client: {e}")
    
    def invoke_model(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4000,
        temperature: float = 0.1,
        top_p: float = 0.9,
        model_id: Optional[str] = None
    ) -> BedrockResponse:
        """
        Invoke a Bedrock model with the given prompt.
        
        Args:
            prompt: User prompt for the model
            system_prompt: Optional system prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature (0.0 to 1.0)
            top_p: Top-p sampling parameter
            model_id: Model ID to use (defaults to config model)
            
        Returns:
            BedrockResponse with model output and metadata
            
        Raises:
            BedrockClientError: If the API call fails
        """
        model_id = model_id or self.config.model
        
        # Prepare request body based on model type
        if "anthropic.claude" in model_id:
            body = self._prepare_claude_request(
                prompt, system_prompt, max_tokens, temperature, top_p
            )
        else:
            raise BedrockClientError(f"Unsupported model: {model_id}")
        
        # Make API call with retry logic
        return self._invoke_with_retry(model_id, body)
    
    def _prepare_claude_request(
        self,
        prompt: str,
        system_prompt: Optional[str],
        max_tokens: int,
        temperature: float,
        top_p: float
    ) -> Dict[str, Any]:
        """Prepare request body for Claude models."""
        messages = [{"role": "user", "content": prompt}]
        
        body = {
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": top_p,
            "anthropic_version": "bedrock-2023-05-31"
        }
        
        if system_prompt:
            body["system"] = system_prompt
        
        return body
    
    def _invoke_with_retry(self, model_id: str, body: Dict[str, Any]) -> BedrockResponse:
        """
        Invoke model with exponential backoff retry logic.
        
        Args:
            model_id: Model identifier
            body: Request body
            
        Returns:
            BedrockResponse with model output
            
        Raises:
            BedrockClientError: If all retries fail
        """
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                logger.debug(f"Invoking model {model_id}, attempt {attempt + 1}")
                
                response = self._client.invoke_model(
                    modelId=model_id,
                    body=json.dumps(body),
                    contentType='application/json',
                    accept='application/json'
                )
                
                return self._parse_response(response, model_id)
                
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                error_message = e.response.get('Error', {}).get('Message', str(e))
                
                logger.warning(f"Bedrock API error (attempt {attempt + 1}): {error_code} - {error_message}")
                
                # Handle specific error types
                if error_code == 'ThrottlingException':
                    if attempt < self.max_retries:
                        delay = self._calculate_retry_delay(attempt)
                        logger.info(f"Rate limited, retrying in {delay} seconds...")
                        time.sleep(delay)
                        continue
                    else:
                        raise BedrockClientError(
                            f"Rate limit exceeded after {self.max_retries} retries",
                            error_code=error_code
                        )
                
                elif error_code in ['ValidationException', 'AccessDeniedException']:
                    # Don't retry these errors
                    raise BedrockClientError(
                        f"API error: {error_message}",
                        error_code=error_code
                    )
                
                else:
                    # Retry other errors
                    last_exception = e
                    if attempt < self.max_retries:
                        delay = self._calculate_retry_delay(attempt)
                        logger.info(f"Retrying in {delay} seconds...")
                        time.sleep(delay)
                        continue
            
            except (BotoCoreError, Exception) as e:
                logger.warning(f"Unexpected error (attempt {attempt + 1}): {e}")
                last_exception = e
                if attempt < self.max_retries:
                    delay = self._calculate_retry_delay(attempt)
                    time.sleep(delay)
                    continue
        
        # All retries failed
        raise BedrockClientError(
            f"Failed to invoke model after {self.max_retries + 1} attempts: {last_exception}"
        )
    
    def _calculate_retry_delay(self, attempt: int) -> float:
        """Calculate exponential backoff delay."""
        delay = self.base_delay * (2 ** attempt)
        return min(delay, self.max_delay)
    
    def _parse_response(self, response: Dict[str, Any], model_id: str) -> BedrockResponse:
        """
        Parse Bedrock API response.
        
        Args:
            response: Raw API response
            model_id: Model identifier
            
        Returns:
            Parsed BedrockResponse
        """
        try:
            body = json.loads(response['body'].read())
            
            if "anthropic.claude" in model_id:
                return self._parse_claude_response(body, model_id)
            else:
                raise BedrockClientError(f"Unsupported model for parsing: {model_id}")
                
        except (json.JSONDecodeError, KeyError) as e:
            raise BedrockClientError(f"Failed to parse response: {e}")
    
    def _parse_claude_response(self, body: Dict[str, Any], model_id: str) -> BedrockResponse:
        """Parse Claude model response."""
        try:
            content = body['content'][0]['text']
            usage = body.get('usage', {})
            
            return BedrockResponse(
                content=content,
                model_id=model_id,
                input_tokens=usage.get('input_tokens', 0),
                output_tokens=usage.get('output_tokens', 0),
                stop_reason=body.get('stop_reason'),
                metadata=body
            )
            
        except (KeyError, IndexError) as e:
            raise BedrockClientError(f"Invalid Claude response format: {e}")
    
    def test_connection(self) -> bool:
        """
        Test the Bedrock connection with a simple prompt.
        
        Returns:
            True if connection is successful, False otherwise
        """
        try:
            response = self.invoke_model(
                prompt="Hello, please respond with 'Connection successful'",
                max_tokens=50,
                temperature=0.0
            )
            
            success = "connection successful" in response.content.lower()
            if success:
                logger.info("Bedrock connection test successful")
            else:
                logger.warning("Bedrock connection test failed - unexpected response")
            
            return success
            
        except Exception as e:
            logger.error(f"Bedrock connection test failed: {e}")
            return False
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the configured model.
        
        Returns:
            Dictionary with model information
        """
        return {
            "model_id": self.config.model,
            "region": self.config.region,
            "timeout_seconds": self.config.timeout_seconds,
            "max_retries": self.max_retries
        }
    
    def estimate_tokens(self, text: str) -> int:
        """
        Estimate token count for given text.
        
        This is a rough approximation - actual token count may vary.
        
        Args:
            text: Input text
            
        Returns:
            Estimated token count
        """
        # Rough approximation: 1 token ≈ 4 characters for English text
        return len(text) // 4
    
    def batch_invoke(
        self,
        prompts: List[str],
        system_prompt: Optional[str] = None,
        max_tokens: int = 4000,
        temperature: float = 0.1,
        concurrent_limit: int = 3
    ) -> List[BedrockResponse]:
        """
        Invoke model with multiple prompts sequentially.
        
        Note: This is a sequential implementation. For true concurrency,
        consider using asyncio in a future version.
        
        Args:
            prompts: List of prompts to process
            system_prompt: Optional system prompt for all requests
            max_tokens: Maximum tokens per response
            temperature: Sampling temperature
            concurrent_limit: Maximum concurrent requests (not used in this implementation)
            
        Returns:
            List of BedrockResponse objects
        """
        responses = []
        
        for i, prompt in enumerate(prompts):
            logger.info(f"Processing prompt {i + 1}/{len(prompts)}")
            
            try:
                response = self.invoke_model(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    max_tokens=max_tokens,
                    temperature=temperature
                )
                responses.append(response)
                
            except BedrockClientError as e:
                logger.error(f"Failed to process prompt {i + 1}: {e}")
                # Create error response
                error_response = BedrockResponse(
                    content=f"Error: {e}",
                    model_id=self.config.model,
                    input_tokens=0,
                    output_tokens=0,
                    stop_reason="error"
                )
                responses.append(error_response)
        
        return responses