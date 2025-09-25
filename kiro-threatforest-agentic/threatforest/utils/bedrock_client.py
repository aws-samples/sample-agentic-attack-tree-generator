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
from datetime import datetime, timedelta

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


@dataclass
class ModelInfo:
    """Information about a Bedrock foundation model."""
    
    model_id: str
    model_name: str
    provider_name: str
    input_modalities: List[str]
    output_modalities: List[str]
    supported_inference_types: List[str]
    model_lifecycle_status: str
    customizations_supported: List[str] = None
    inference_types_supported: List[str] = None


@dataclass
class InferenceProfileInfo:
    """Information about a Bedrock inference profile."""
    
    inference_profile_id: str
    inference_profile_name: str
    description: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    models: List[Dict[str, Any]]
    status: str
    type: str  # APPLICATION or SYSTEM
    inference_profile_arn: Optional[str] = None


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
        self._bedrock_client = None  # For model discovery operations
        self._session = None
        
        # Retry configuration
        self.max_retries = 3
        self.base_delay = 1.0
        self.max_delay = 60.0
        
        # Model discovery cache
        self._model_cache: Dict[str, Any] = {}
        self._cache_expiry: Optional[datetime] = None
        self._cache_duration = timedelta(hours=1)  # Cache for 1 hour
        
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
            
            # Create Bedrock runtime client for model invocation
            self._client = self._session.client(
                'bedrock-runtime',
                config=client_config
            )
            
            # Create Bedrock client for model discovery and management
            self._bedrock_client = self._session.client(
                'bedrock',
                config=client_config
            )
            
            # Verify client initialization
            logger.debug(f"Bedrock runtime client endpoint: {self._client._endpoint.host}")
            logger.debug(f"Bedrock client endpoint: {self._bedrock_client._endpoint.host}")
            
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
        
        # Determine if this is an inference profile ARN or regular model ID
        is_inference_profile = self._is_inference_profile_arn(model_id)
        
        if is_inference_profile:
            # For inference profiles, use the ARN directly and extract underlying model type
            effective_model_id = model_id
            underlying_model_id = self._extract_underlying_model_from_arn(model_id)
        else:
            # For regular models, check if they need inference profile mapping
            effective_model_id = self._get_effective_model_id(model_id)
            underlying_model_id = model_id
        
        # Prepare request body based on underlying model type
        if "anthropic.claude" in underlying_model_id:
            body = self._prepare_claude_request(
                prompt, system_prompt, max_tokens, temperature, top_p
            )
        else:
            raise BedrockClientError(f"Unsupported model: {model_id}")
        
        # Make API call with retry logic
        return self._invoke_with_retry(effective_model_id, body, original_model_id=model_id, underlying_model_id=underlying_model_id)
    
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
    
    def _get_effective_model_id(self, model_id: str) -> str:
        """
        Get the effective model ID, handling inference profiles for models that require them.
        
        Args:
            model_id: Original model ID
            
        Returns:
            Effective model ID (may be an inference profile ARN)
        """
        # Models that require inference profiles
        inference_profile_models = {
            "anthropic.claude-sonnet-4-20250514-v1:0": "us.anthropic.claude-sonnet-4-20250514-v1:0",
            "anthropic.claude-opus-4-20250514-v1:0": "us.anthropic.claude-opus-4-20250514-v1:0",
            "anthropic.claude-opus-4-1-20250805-v1:0": "us.anthropic.claude-opus-4-1-20250805-v1:0",
            "anthropic.claude-3-7-sonnet-20250219-v1:0": "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
        }
        
        # Check if this model requires an inference profile
        if model_id in inference_profile_models:
            inference_profile_id = inference_profile_models[model_id]
            logger.info(f"Using inference profile {inference_profile_id} for model {model_id}")
            return inference_profile_id
        
        return model_id
    
    def _is_inference_profile_arn(self, model_id: str) -> bool:
        """
        Check if the model_id is an inference profile ARN.
        
        Args:
            model_id: Model ID or inference profile ARN
            
        Returns:
            True if it's an inference profile ARN, False otherwise
        """
        # Inference profile ARNs have the format:
        # arn:aws:bedrock:region:account:inference-profile/profile-id
        # or just the profile ID like: us.anthropic.claude-sonnet-4-20250514-v1:0
        
        if model_id.startswith('arn:aws:bedrock:') and 'inference-profile' in model_id:
            return True
        
        # Check for cross-region inference profile IDs (start with region prefix)
        if model_id.startswith('us.') or model_id.startswith('eu.') or model_id.startswith('ap.'):
            return True
        
        return False
    
    def _extract_underlying_model_from_arn(self, arn_or_profile_id: str) -> str:
        """
        Extract the underlying model ID from an inference profile ARN or ID.
        
        Args:
            arn_or_profile_id: Inference profile ARN or profile ID
            
        Returns:
            Underlying model ID for determining request format
        """
        # For cross-region inference profile IDs, extract the model part
        if arn_or_profile_id.startswith('us.') or arn_or_profile_id.startswith('eu.') or arn_or_profile_id.startswith('ap.'):
            # Format: us.anthropic.claude-sonnet-4-20250514-v1:0
            # Extract: anthropic.claude-sonnet-4-20250514-v1:0
            parts = arn_or_profile_id.split('.', 1)
            if len(parts) > 1:
                return parts[1]
        
        # For full ARNs, we need to map back to the underlying model
        # This is more complex and would require additional metadata
        # For now, make educated guesses based on the profile ID
        if 'claude' in arn_or_profile_id.lower():
            if 'sonnet-4' in arn_or_profile_id:
                return 'anthropic.claude-sonnet-4-20250514-v1:0'
            elif 'opus-4' in arn_or_profile_id:
                return 'anthropic.claude-opus-4-20250514-v1:0'
            elif 'sonnet' in arn_or_profile_id:
                return 'anthropic.claude-3-5-sonnet-20241022-v2:0'
            else:
                return 'anthropic.claude-3-haiku-20240307-v1:0'
        
        # Default fallback - assume it's a Claude model
        return 'anthropic.claude-3-5-sonnet-20241022-v2:0'
    
    def _get_alternative_model(self, model_id: str) -> Optional[str]:
        """
        Get an alternative model that doesn't require inference profiles.
        
        Args:
            model_id: Original model ID that failed
            
        Returns:
            Alternative model ID or None
        """
        # Map problematic models to working alternatives
        alternatives = {
            "anthropic.claude-sonnet-4-20250514-v1:0": "anthropic.claude-3-5-sonnet-20241022-v2:0",
            "anthropic.claude-opus-4-20250514-v1:0": "anthropic.claude-3-opus-20240229-v1:0",
            "anthropic.claude-opus-4-1-20250805-v1:0": "anthropic.claude-3-opus-20240229-v1:0",
            "anthropic.claude-3-7-sonnet-20250219-v1:0": "anthropic.claude-3-5-sonnet-20241022-v2:0"
        }
        
        return alternatives.get(model_id)
    
    def _invoke_with_retry(self, model_id: str, body: Dict[str, Any], original_model_id: Optional[str] = None, underlying_model_id: Optional[str] = None) -> BedrockResponse:
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
                
                return self._parse_response(response, original_model_id or model_id, underlying_model_id)
                
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
                    # Check if it's the inference profile error
                    if "inference profile" in error_message.lower() and "on-demand throughput" in error_message.lower():
                        # Try to suggest an alternative model
                        suggested_model = self._get_alternative_model(original_model_id or model_id)
                        if suggested_model:
                            raise BedrockClientError(
                                f"Model {original_model_id or model_id} requires an inference profile. "
                                f"Try using {suggested_model} instead, or contact your AWS administrator "
                                f"to set up inference profiles for this model.",
                                error_code=error_code
                            )
                    
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
    
    def _parse_response(self, response: Dict[str, Any], model_id: str, underlying_model_id: Optional[str] = None) -> BedrockResponse:
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
            
            # Use underlying model ID for determining response format, fallback to model_id
            parse_model_id = underlying_model_id or model_id
            
            if "anthropic.claude" in parse_model_id:
                return self._parse_claude_response(body, model_id)
            else:
                raise BedrockClientError(f"Unsupported model for parsing: {parse_model_id}")
                
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
    
    def list_available_models(self, by_provider: Optional[str] = None) -> List[ModelInfo]:
        """
        List available foundation models using Bedrock's ListFoundationModels API.
        
        Args:
            by_provider: Optional provider filter (e.g., 'Anthropic', 'Amazon', 'AI21')
            
        Returns:
            List of ModelInfo objects with model details
            
        Raises:
            BedrockClientError: If the API call fails
        """
        logger.info(f"Listing available models in region {self.config.region}")
        if by_provider:
            logger.info(f"Filtering by provider: {by_provider}")
        
        # Check cache first
        cache_key = f"models_{by_provider or 'all'}_{self.config.region}"
        if self._is_cache_valid() and cache_key in self._model_cache:
            logger.debug("Returning cached model list")
            return self._model_cache[cache_key]
        
        try:
            # Prepare request parameters
            params = {}
            if by_provider:
                params['byProvider'] = by_provider
            
            logger.debug(f"Calling ListFoundationModels API with params: {params}")
            response = self._bedrock_client.list_foundation_models(**params)
            
            models = []
            for model_data in response.get('modelSummaries', []):
                model_info = ModelInfo(
                    model_id=model_data['modelId'],
                    model_name=model_data['modelName'],
                    provider_name=model_data['providerName'],
                    input_modalities=model_data.get('inputModalities', []),
                    output_modalities=model_data.get('outputModalities', []),
                    supported_inference_types=model_data.get('supportedInferenceTypes', []),
                    model_lifecycle_status=model_data.get('modelLifecycle', {}).get('status', 'UNKNOWN'),
                    customizations_supported=model_data.get('customizationsSupported', []),
                    inference_types_supported=model_data.get('inferenceTypesSupported', [])
                )
                models.append(model_info)
            
            logger.info(f"Found {len(models)} available models")
            
            # Cache the results
            self._model_cache[cache_key] = models
            self._cache_expiry = datetime.now() + self._cache_duration
            
            return models
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            logger.error(f"Failed to list models: {error_code} - {error_message}")
            raise BedrockClientError(f"Failed to list available models: {error_message}", error_code=error_code)
        
        except Exception as e:
            logger.error(f"Unexpected error listing models: {e}")
            raise BedrockClientError(f"Unexpected error listing models: {e}")
    
    def list_inference_profiles(self, max_results: Optional[int] = None) -> List[InferenceProfileInfo]:
        """
        List available inference profiles using Bedrock's ListInferenceProfiles API.
        
        Args:
            max_results: Maximum number of results to return
            
        Returns:
            List of InferenceProfileInfo objects with profile details
            
        Raises:
            BedrockClientError: If the API call fails
        """
        logger.info(f"Listing available inference profiles in region {self.config.region}")
        
        # Check cache first
        cache_key = f"inference_profiles_{self.config.region}_{max_results or 'all'}"
        if self._is_cache_valid() and cache_key in self._model_cache:
            logger.debug("Returning cached inference profiles list")
            return self._model_cache[cache_key]
        
        try:
            # Prepare request parameters
            params = {}
            if max_results:
                params['maxResults'] = max_results
            
            logger.debug(f"Calling ListInferenceProfiles API with params: {params}")
            response = self._bedrock_client.list_inference_profiles(**params)
            
            profiles = []
            for profile_data in response.get('inferenceProfileSummaries', []):
                # Parse datetime fields
                created_at = None
                updated_at = None
                
                if 'createdAt' in profile_data:
                    created_at = profile_data['createdAt']
                    if isinstance(created_at, str):
                        try:
                            created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                        except ValueError:
                            created_at = None
                
                if 'updatedAt' in profile_data:
                    updated_at = profile_data['updatedAt']
                    if isinstance(updated_at, str):
                        try:
                            updated_at = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
                        except ValueError:
                            updated_at = None
                
                profile_info = InferenceProfileInfo(
                    inference_profile_id=profile_data['inferenceProfileId'],
                    inference_profile_name=profile_data.get('inferenceProfileName', profile_data['inferenceProfileId']),
                    description=profile_data.get('description'),
                    created_at=created_at,
                    updated_at=updated_at,
                    models=profile_data.get('models', []),
                    status=profile_data.get('status', 'UNKNOWN'),
                    type=profile_data.get('type', 'UNKNOWN'),
                    inference_profile_arn=profile_data.get('inferenceProfileArn')
                )
                profiles.append(profile_info)
            
            logger.info(f"Found {len(profiles)} available inference profiles")
            
            # Cache the results
            self._model_cache[cache_key] = profiles
            self._cache_expiry = datetime.now() + self._cache_duration
            
            return profiles
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            
            # Handle case where inference profiles are not available in the region
            if error_code in ['ResourceNotFoundException', 'ValidationException']:
                logger.info(f"Inference profiles not available in region {self.config.region}: {error_message}")
                return []
            
            logger.error(f"Failed to list inference profiles: {error_code} - {error_message}")
            raise BedrockClientError(f"Failed to list inference profiles: {error_message}", error_code=error_code)
        
        except Exception as e:
            logger.error(f"Unexpected error listing inference profiles: {e}")
            raise BedrockClientError(f"Unexpected error listing inference profiles: {e}")
    
    def validate_model_region_compatibility(self, model_id: str, region: Optional[str] = None) -> bool:
        """
        Validate that a model is available in the specified region.
        
        Args:
            model_id: Model identifier to validate
            region: AWS region to check (defaults to current config region)
            
        Returns:
            True if model is available in the region, False otherwise
        """
        check_region = region or self.config.region
        logger.info(f"Validating model {model_id} compatibility with region {check_region}")
        
        try:
            # If checking a different region, create a temporary client
            if region and region != self.config.region:
                logger.debug(f"Creating temporary client for region {region}")
                temp_session = boto3.Session()
                temp_client = temp_session.client('bedrock', region_name=region)
                bedrock_client = temp_client
            else:
                bedrock_client = self._bedrock_client
            
            # Try to get model details - this will fail if model is not available
            logger.debug(f"Checking model availability via GetFoundationModel API")
            response = bedrock_client.get_foundation_model(modelIdentifier=model_id)
            
            model_details = response.get('modelDetails', {})
            lifecycle_status = model_details.get('modelLifecycle', {}).get('status', 'UNKNOWN')
            
            is_active = lifecycle_status == 'ACTIVE'
            logger.info(f"Model {model_id} in region {check_region}: status={lifecycle_status}, compatible={is_active}")
            
            return is_active
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            
            if error_code in ['ResourceNotFoundException', 'ValidationException']:
                logger.warning(f"Model {model_id} not available in region {check_region}: {error_code}")
                return False
            else:
                logger.error(f"Error validating model compatibility: {error_code}")
                raise BedrockClientError(f"Error validating model compatibility: {e}")
        
        except Exception as e:
            logger.error(f"Unexpected error validating model compatibility: {e}")
            raise BedrockClientError(f"Unexpected error validating model compatibility: {e}")
    
    def get_model_recommendations(self, use_case: str = "general") -> List[ModelInfo]:
        """
        Get model recommendations based on use case.
        
        Args:
            use_case: Use case for recommendations ('general', 'analysis', 'creative', 'coding')
            
        Returns:
            List of recommended ModelInfo objects
        """
        logger.info(f"Getting model recommendations for use case: {use_case}")
        
        # Get all available models
        all_models = self.list_available_models()
        
        # Define use case preferences
        use_case_preferences = {
            "general": {
                "preferred_providers": ["Anthropic", "Amazon"],
                "required_modalities": ["TEXT"],
                "model_patterns": ["claude", "titan"]
            },
            "analysis": {
                "preferred_providers": ["Anthropic"],
                "required_modalities": ["TEXT"],
                "model_patterns": ["claude-3", "claude-2"]
            },
            "creative": {
                "preferred_providers": ["Anthropic", "AI21"],
                "required_modalities": ["TEXT"],
                "model_patterns": ["claude", "jurassic"]
            },
            "coding": {
                "preferred_providers": ["Anthropic", "Amazon"],
                "required_modalities": ["TEXT"],
                "model_patterns": ["claude", "titan"]
            }
        }
        
        preferences = use_case_preferences.get(use_case, use_case_preferences["general"])
        logger.debug(f"Using preferences: {preferences}")
        
        recommended_models = []
        
        for model in all_models:
            # Check if model is active
            if model.model_lifecycle_status != 'ACTIVE':
                continue
            
            # Check required modalities
            if not all(mod in model.input_modalities + model.output_modalities 
                      for mod in preferences["required_modalities"]):
                continue
            
            # Score model based on preferences
            score = 0
            
            # Provider preference
            if model.provider_name in preferences["preferred_providers"]:
                score += 10
            
            # Model pattern matching
            model_id_lower = model.model_id.lower()
            for pattern in preferences["model_patterns"]:
                if pattern in model_id_lower:
                    score += 5
                    break
            
            # Prefer models that support on-demand inference
            if 'ON_DEMAND' in model.supported_inference_types:
                score += 3
            
            if score > 0:
                recommended_models.append((model, score))
        
        # Sort by score (descending) and return top models
        recommended_models.sort(key=lambda x: x[1], reverse=True)
        result = [model for model, score in recommended_models[:5]]  # Top 5 recommendations
        
        logger.info(f"Returning {len(result)} model recommendations for use case '{use_case}'")
        for model in result:
            logger.debug(f"Recommended: {model.model_id} ({model.provider_name})")
        
        return result
    
    def _is_cache_valid(self) -> bool:
        """Check if the model cache is still valid."""
        if self._cache_expiry is None:
            return False
        return datetime.now() < self._cache_expiry
    
    def clear_model_cache(self) -> None:
        """Clear the model discovery cache."""
        logger.debug("Clearing model discovery cache")
        self._model_cache.clear()
        self._cache_expiry = None
    
    def get_sdk_info(self) -> Dict[str, str]:
        """
        Get information about the AWS SDK being used.
        
        Returns:
            Dictionary with SDK version and client information
        """
        import boto3
        import botocore
        
        return {
            "boto3_version": boto3.__version__,
            "botocore_version": botocore.__version__,
            "bedrock_runtime_endpoint": getattr(self._client._endpoint, 'host', 'unknown'),
            "bedrock_endpoint": getattr(self._bedrock_client._endpoint, 'host', 'unknown'),
            "region": self.config.region,
            "service_model_version": getattr(self._client._service_model, 'api_version', 'unknown')
        }
    
    def verify_bedrock_access(self) -> Dict[str, Any]:
        """
        Verify Bedrock service access and permissions.
        
        Returns:
            Dictionary with verification results
        """
        verification_results = {
            "bedrock_runtime_access": False,
            "bedrock_access": False,
            "model_list_access": False,
            "model_invoke_access": False,
            "errors": []
        }
        
        # Test Bedrock service access
        try:
            # Test basic Bedrock access by listing models
            models = self._bedrock_client.list_foundation_models()
            verification_results["bedrock_access"] = True
            verification_results["model_list_access"] = True
            logger.info(f"Bedrock access verified - found {len(models.get('modelSummaries', []))} models")
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_msg = f"Bedrock access failed: {error_code}"
            verification_results["errors"].append(error_msg)
            logger.error(error_msg)
        except Exception as e:
            error_msg = f"Bedrock access error: {e}"
            verification_results["errors"].append(error_msg)
            logger.error(error_msg)
        
        # Test Bedrock Runtime access with a simple invocation
        try:
            # Use a minimal test prompt
            test_response = self.invoke_model(
                prompt="Test",
                max_tokens=10,
                temperature=0.0
            )
            verification_results["bedrock_runtime_access"] = True
            verification_results["model_invoke_access"] = True
            logger.info("Bedrock Runtime access verified - model invocation successful")
        except BedrockClientError as e:
            error_msg = f"Bedrock Runtime access failed: {e}"
            verification_results["errors"].append(error_msg)
            logger.error(error_msg)
        except Exception as e:
            error_msg = f"Bedrock Runtime error: {e}"
            verification_results["errors"].append(error_msg)
            logger.error(error_msg)
        
        return verification_results

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