"""
Unit tests for Bedrock client integration.
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError

from threatforest.config import BedrockConfig
from threatforest.utils.bedrock_client import (
    BedrockClient,
    BedrockResponse,
    BedrockClientError,
    ModelInfo
)


class TestBedrockResponse:
    """Test cases for BedrockResponse dataclass."""
    
    def test_bedrock_response_creation(self):
        """Test basic BedrockResponse creation."""
        response = BedrockResponse(
            content="Test response",
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            input_tokens=10,
            output_tokens=20,
            stop_reason="end_turn"
        )
        
        assert response.content == "Test response"
        assert response.model_id == "anthropic.claude-3-sonnet-20240229-v1:0"
        assert response.input_tokens == 10
        assert response.output_tokens == 20
        assert response.stop_reason == "end_turn"


class TestBedrockClientError:
    """Test cases for BedrockClientError exception."""
    
    def test_bedrock_client_error_basic(self):
        """Test basic BedrockClientError creation."""
        error = BedrockClientError("Test error")
        assert str(error) == "Test error"
        assert error.error_code is None
        assert error.retry_after is None
    
    def test_bedrock_client_error_with_details(self):
        """Test BedrockClientError with error code and retry info."""
        error = BedrockClientError(
            "Rate limit exceeded",
            error_code="ThrottlingException",
            retry_after=60
        )
        
        assert str(error) == "Rate limit exceeded"
        assert error.error_code == "ThrottlingException"
        assert error.retry_after == 60


class TestBedrockClient:
    """Test cases for BedrockClient class."""
    
    def setup_method(self):
        """Set up test environment."""
        self.config = BedrockConfig(
            region="us-east-1",
            model="anthropic.claude-3-sonnet-20240229-v1:0",
            timeout_seconds=300
        )
    
    @patch('boto3.Session')
    def test_client_initialization_success(self, mock_session):
        """Test successful client initialization."""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        client = BedrockClient(self.config)
        
        assert client.config == self.config
        assert client._client == mock_client
        mock_session.assert_called_once()
    
    @patch('boto3.Session')
    def test_client_initialization_failure(self, mock_session):
        """Test client initialization failure."""
        mock_session.side_effect = Exception("AWS error")
        
        with pytest.raises(BedrockClientError, match="Failed to initialize Bedrock client"):
            BedrockClient(self.config)
    
    @patch('boto3.Session')
    def test_invoke_model_success(self, mock_session):
        """Test successful model invocation."""
        # Mock the Bedrock client
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        # Mock successful response
        mock_response = {
            'body': Mock()
        }
        mock_response['body'].read.return_value = json.dumps({
            'content': [{'text': 'Test response'}],
            'usage': {'input_tokens': 10, 'output_tokens': 20},
            'stop_reason': 'end_turn'
        }).encode()
        
        mock_client.invoke_model.return_value = mock_response
        
        client = BedrockClient(self.config)
        response = client.invoke_model("Test prompt")
        
        assert isinstance(response, BedrockResponse)
        assert response.content == "Test response"
        assert response.input_tokens == 10
        assert response.output_tokens == 20
        assert response.stop_reason == "end_turn"
    
    @patch('boto3.Session')
    def test_invoke_model_with_system_prompt(self, mock_session):
        """Test model invocation with system prompt."""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        mock_response = {
            'body': Mock()
        }
        mock_response['body'].read.return_value = json.dumps({
            'content': [{'text': 'Response with system prompt'}],
            'usage': {'input_tokens': 15, 'output_tokens': 25},
            'stop_reason': 'end_turn'
        }).encode()
        
        mock_client.invoke_model.return_value = mock_response
        
        client = BedrockClient(self.config)
        response = client.invoke_model(
            prompt="User prompt",
            system_prompt="System instructions"
        )
        
        # Verify the request body includes system prompt
        call_args = mock_client.invoke_model.call_args
        body = json.loads(call_args[1]['body'])
        assert 'system' in body
        assert body['system'] == "System instructions"
        
        assert response.content == "Response with system prompt"
    
    @patch('boto3.Session')
    def test_invoke_model_unsupported_model(self, mock_session):
        """Test model invocation with unsupported model."""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        # Use unsupported model
        config = BedrockConfig(model="unsupported.model")
        client = BedrockClient(config)
        
        with pytest.raises(BedrockClientError, match="Unsupported model"):
            client.invoke_model("Test prompt")
    
    @patch('boto3.Session')
    @patch('time.sleep')  # Mock sleep to speed up tests
    def test_invoke_model_throttling_retry(self, mock_sleep, mock_session):
        """Test retry logic for throttling errors."""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        # First call raises throttling exception, second succeeds
        throttling_error = ClientError(
            error_response={
                'Error': {
                    'Code': 'ThrottlingException',
                    'Message': 'Rate exceeded'
                }
            },
            operation_name='InvokeModel'
        )
        
        mock_response = {
            'body': Mock()
        }
        mock_response['body'].read.return_value = json.dumps({
            'content': [{'text': 'Success after retry'}],
            'usage': {'input_tokens': 10, 'output_tokens': 20},
            'stop_reason': 'end_turn'
        }).encode()
        
        mock_client.invoke_model.side_effect = [throttling_error, mock_response]
        
        client = BedrockClient(self.config)
        response = client.invoke_model("Test prompt")
        
        assert response.content == "Success after retry"
        assert mock_client.invoke_model.call_count == 2
        mock_sleep.assert_called_once()
    
    @patch('boto3.Session')
    def test_invoke_model_validation_error_no_retry(self, mock_session):
        """Test that validation errors are not retried."""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        validation_error = ClientError(
            error_response={
                'Error': {
                    'Code': 'ValidationException',
                    'Message': 'Invalid request'
                }
            },
            operation_name='InvokeModel'
        )
        
        mock_client.invoke_model.side_effect = validation_error
        
        client = BedrockClient(self.config)
        
        with pytest.raises(BedrockClientError, match="API error: Invalid request"):
            client.invoke_model("Test prompt")
        
        # Should only be called once (no retries)
        assert mock_client.invoke_model.call_count == 1
    
    @patch('boto3.Session')
    @patch('time.sleep')
    def test_invoke_model_max_retries_exceeded(self, mock_sleep, mock_session):
        """Test behavior when max retries are exceeded."""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        # Always raise throttling exception
        throttling_error = ClientError(
            error_response={
                'Error': {
                    'Code': 'ThrottlingException',
                    'Message': 'Rate exceeded'
                }
            },
            operation_name='InvokeModel'
        )
        
        mock_client.invoke_model.side_effect = throttling_error
        
        client = BedrockClient(self.config)
        
        with pytest.raises(BedrockClientError, match="Rate limit exceeded after .* retries"):
            client.invoke_model("Test prompt")
        
        # Should be called max_retries + 1 times
        assert mock_client.invoke_model.call_count == client.max_retries + 1
    
    @patch('boto3.Session')
    def test_test_connection_success(self, mock_session):
        """Test successful connection test."""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        mock_response = {
            'body': Mock()
        }
        mock_response['body'].read.return_value = json.dumps({
            'content': [{'text': 'Connection successful'}],
            'usage': {'input_tokens': 5, 'output_tokens': 10},
            'stop_reason': 'end_turn'
        }).encode()
        
        mock_client.invoke_model.return_value = mock_response
        
        client = BedrockClient(self.config)
        assert client.test_connection() is True
    
    @patch('boto3.Session')
    def test_test_connection_failure(self, mock_session):
        """Test connection test failure."""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        mock_client.invoke_model.side_effect = Exception("Connection failed")
        
        client = BedrockClient(self.config)
        assert client.test_connection() is False
    
    @patch('boto3.Session')
    def test_get_model_info(self, mock_session):
        """Test getting model information."""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        client = BedrockClient(self.config)
        info = client.get_model_info()
        
        assert info['model_id'] == self.config.model
        assert info['region'] == self.config.region
        assert info['timeout_seconds'] == self.config.timeout_seconds
        assert 'max_retries' in info
    
    def test_estimate_tokens(self):
        """Test token estimation."""
        with patch('boto3.Session'):
            client = BedrockClient(self.config)
            
            # Test with known text
            text = "This is a test sentence with multiple words."
            estimated = client.estimate_tokens(text)
            
            # Should be roughly len(text) // 4
            expected = len(text) // 4
            assert estimated == expected
    
    @patch('boto3.Session')
    def test_batch_invoke_success(self, mock_session):
        """Test successful batch invocation."""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        # Mock responses for multiple prompts
        responses = []
        for i in range(3):
            mock_response = {
                'body': Mock()
            }
            mock_response['body'].read.return_value = json.dumps({
                'content': [{'text': f'Response {i + 1}'}],
                'usage': {'input_tokens': 10, 'output_tokens': 20},
                'stop_reason': 'end_turn'
            }).encode()
            responses.append(mock_response)
        
        mock_client.invoke_model.side_effect = responses
        
        client = BedrockClient(self.config)
        prompts = ["Prompt 1", "Prompt 2", "Prompt 3"]
        results = client.batch_invoke(prompts)
        
        assert len(results) == 3
        for i, result in enumerate(results):
            assert result.content == f"Response {i + 1}"
        
        assert mock_client.invoke_model.call_count == 3
    
    @patch('boto3.Session')
    def test_batch_invoke_with_error(self, mock_session):
        """Test batch invocation with one failure."""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        # First call succeeds, second fails, third succeeds
        success_response = {
            'body': Mock()
        }
        success_response['body'].read.return_value = json.dumps({
            'content': [{'text': 'Success'}],
            'usage': {'input_tokens': 10, 'output_tokens': 20},
            'stop_reason': 'end_turn'
        }).encode()
        
        error = ClientError(
            error_response={
                'Error': {
                    'Code': 'ValidationException',
                    'Message': 'Invalid request'
                }
            },
            operation_name='InvokeModel'
        )
        
        mock_client.invoke_model.side_effect = [success_response, error, success_response]
        
        client = BedrockClient(self.config)
        prompts = ["Prompt 1", "Prompt 2", "Prompt 3"]
        results = client.batch_invoke(prompts)
        
        assert len(results) == 3
        assert results[0].content == "Success"
        assert "Error:" in results[1].content  # Error response
        assert results[2].content == "Success"
    
    def test_calculate_retry_delay(self):
        """Test retry delay calculation."""
        with patch('boto3.Session'):
            client = BedrockClient(self.config)
            
            # Test exponential backoff
            delay_0 = client._calculate_retry_delay(0)
            delay_1 = client._calculate_retry_delay(1)
            delay_2 = client._calculate_retry_delay(2)
            
            assert delay_0 == 1.0  # base_delay * 2^0
            assert delay_1 == 2.0  # base_delay * 2^1
            assert delay_2 == 4.0  # base_delay * 2^2
            
            # Test max delay cap
            delay_large = client._calculate_retry_delay(10)
            assert delay_large == client.max_delay


class TestModelInfo:
    """Test cases for ModelInfo dataclass."""
    
    def test_model_info_creation(self):
        """Test basic ModelInfo creation."""
        model_info = ModelInfo(
            model_id="anthropic.claude-3-sonnet-20240229-v1:0",
            model_name="Claude 3 Sonnet",
            provider_name="Anthropic",
            input_modalities=["TEXT"],
            output_modalities=["TEXT"],
            supported_inference_types=["ON_DEMAND"],
            model_lifecycle_status="ACTIVE"
        )
        
        assert model_info.model_id == "anthropic.claude-3-sonnet-20240229-v1:0"
        assert model_info.model_name == "Claude 3 Sonnet"
        assert model_info.provider_name == "Anthropic"
        assert model_info.input_modalities == ["TEXT"]
        assert model_info.output_modalities == ["TEXT"]
        assert model_info.supported_inference_types == ["ON_DEMAND"]
        assert model_info.model_lifecycle_status == "ACTIVE"


class TestBedrockClientModelDiscovery:
    """Test cases for model discovery methods in BedrockClient."""
    
    def setup_method(self):
        """Set up test environment."""
        self.config = BedrockConfig(
            region="us-east-1",
            model="anthropic.claude-3-sonnet-20240229-v1:0",
            timeout_seconds=300
        )
    
    @patch('boto3.Session')
    def test_list_available_models_success(self, mock_session):
        """Test successful model listing."""
        mock_runtime_client = Mock()
        mock_bedrock_client = Mock()
        mock_session.return_value.client.side_effect = [mock_runtime_client, mock_bedrock_client]
        
        # Mock successful response
        mock_response = {
            'modelSummaries': [
                {
                    'modelId': 'anthropic.claude-3-sonnet-20240229-v1:0',
                    'modelName': 'Claude 3 Sonnet',
                    'providerName': 'Anthropic',
                    'inputModalities': ['TEXT'],
                    'outputModalities': ['TEXT'],
                    'supportedInferenceTypes': ['ON_DEMAND'],
                    'modelLifecycle': {'status': 'ACTIVE'},
                    'customizationsSupported': [],
                    'inferenceTypesSupported': ['ON_DEMAND']
                },
                {
                    'modelId': 'amazon.titan-text-express-v1',
                    'modelName': 'Titan Text G1 - Express',
                    'providerName': 'Amazon',
                    'inputModalities': ['TEXT'],
                    'outputModalities': ['TEXT'],
                    'supportedInferenceTypes': ['ON_DEMAND'],
                    'modelLifecycle': {'status': 'ACTIVE'},
                    'customizationsSupported': [],
                    'inferenceTypesSupported': ['ON_DEMAND']
                }
            ]
        }
        
        mock_bedrock_client.list_foundation_models.return_value = mock_response
        
        client = BedrockClient(self.config)
        models = client.list_available_models()
        
        assert len(models) == 2
        assert isinstance(models[0], ModelInfo)
        assert models[0].model_id == 'anthropic.claude-3-sonnet-20240229-v1:0'
        assert models[0].provider_name == 'Anthropic'
        assert models[1].model_id == 'amazon.titan-text-express-v1'
        assert models[1].provider_name == 'Amazon'
        
        mock_bedrock_client.list_foundation_models.assert_called_once_with()
    
    @patch('boto3.Session')
    def test_list_available_models_with_provider_filter(self, mock_session):
        """Test model listing with provider filter."""
        mock_runtime_client = Mock()
        mock_bedrock_client = Mock()
        mock_session.return_value.client.side_effect = [mock_runtime_client, mock_bedrock_client]
        
        mock_response = {
            'modelSummaries': [
                {
                    'modelId': 'anthropic.claude-3-sonnet-20240229-v1:0',
                    'modelName': 'Claude 3 Sonnet',
                    'providerName': 'Anthropic',
                    'inputModalities': ['TEXT'],
                    'outputModalities': ['TEXT'],
                    'supportedInferenceTypes': ['ON_DEMAND'],
                    'modelLifecycle': {'status': 'ACTIVE'},
                    'customizationsSupported': [],
                    'inferenceTypesSupported': ['ON_DEMAND']
                }
            ]
        }
        
        mock_bedrock_client.list_foundation_models.return_value = mock_response
        
        client = BedrockClient(self.config)
        models = client.list_available_models(by_provider="Anthropic")
        
        assert len(models) == 1
        assert models[0].provider_name == 'Anthropic'
        
        mock_bedrock_client.list_foundation_models.assert_called_once_with(byProvider="Anthropic")
    
    @patch('boto3.Session')
    def test_list_available_models_caching(self, mock_session):
        """Test that model listing results are cached."""
        mock_runtime_client = Mock()
        mock_bedrock_client = Mock()
        mock_session.return_value.client.side_effect = [mock_runtime_client, mock_bedrock_client]
        
        mock_response = {
            'modelSummaries': [
                {
                    'modelId': 'anthropic.claude-3-sonnet-20240229-v1:0',
                    'modelName': 'Claude 3 Sonnet',
                    'providerName': 'Anthropic',
                    'inputModalities': ['TEXT'],
                    'outputModalities': ['TEXT'],
                    'supportedInferenceTypes': ['ON_DEMAND'],
                    'modelLifecycle': {'status': 'ACTIVE'},
                    'customizationsSupported': [],
                    'inferenceTypesSupported': ['ON_DEMAND']
                }
            ]
        }
        
        mock_bedrock_client.list_foundation_models.return_value = mock_response
        
        client = BedrockClient(self.config)
        
        # First call should hit the API
        models1 = client.list_available_models()
        assert len(models1) == 1
        
        # Second call should use cache
        models2 = client.list_available_models()
        assert len(models2) == 1
        
        # API should only be called once due to caching
        mock_bedrock_client.list_foundation_models.assert_called_once()
    
    @patch('boto3.Session')
    def test_list_available_models_api_error(self, mock_session):
        """Test model listing API error handling."""
        mock_runtime_client = Mock()
        mock_bedrock_client = Mock()
        mock_session.return_value.client.side_effect = [mock_runtime_client, mock_bedrock_client]
        
        api_error = ClientError(
            error_response={
                'Error': {
                    'Code': 'AccessDeniedException',
                    'Message': 'Access denied'
                }
            },
            operation_name='ListFoundationModels'
        )
        
        mock_bedrock_client.list_foundation_models.side_effect = api_error
        
        client = BedrockClient(self.config)
        
        with pytest.raises(BedrockClientError, match="Failed to list available models"):
            client.list_available_models()
    
    @patch('boto3.Session')
    def test_validate_model_region_compatibility_success(self, mock_session):
        """Test successful model region compatibility validation."""
        mock_runtime_client = Mock()
        mock_bedrock_client = Mock()
        mock_session.return_value.client.side_effect = [mock_runtime_client, mock_bedrock_client]
        
        mock_response = {
            'modelDetails': {
                'modelId': 'anthropic.claude-3-sonnet-20240229-v1:0',
                'modelLifecycle': {'status': 'ACTIVE'}
            }
        }
        
        mock_bedrock_client.get_foundation_model.return_value = mock_response
        
        client = BedrockClient(self.config)
        is_compatible = client.validate_model_region_compatibility(
            'anthropic.claude-3-sonnet-20240229-v1:0'
        )
        
        assert is_compatible is True
        mock_bedrock_client.get_foundation_model.assert_called_once_with(
            modelIdentifier='anthropic.claude-3-sonnet-20240229-v1:0'
        )
    
    @patch('boto3.Session')
    def test_validate_model_region_compatibility_inactive_model(self, mock_session):
        """Test validation with inactive model."""
        mock_runtime_client = Mock()
        mock_bedrock_client = Mock()
        mock_session.return_value.client.side_effect = [mock_runtime_client, mock_bedrock_client]
        
        mock_response = {
            'modelDetails': {
                'modelId': 'anthropic.claude-3-sonnet-20240229-v1:0',
                'modelLifecycle': {'status': 'LEGACY'}
            }
        }
        
        mock_bedrock_client.get_foundation_model.return_value = mock_response
        
        client = BedrockClient(self.config)
        is_compatible = client.validate_model_region_compatibility(
            'anthropic.claude-3-sonnet-20240229-v1:0'
        )
        
        assert is_compatible is False
    
    @patch('boto3.Session')
    def test_validate_model_region_compatibility_not_found(self, mock_session):
        """Test validation with model not found in region."""
        mock_runtime_client = Mock()
        mock_bedrock_client = Mock()
        mock_session.return_value.client.side_effect = [mock_runtime_client, mock_bedrock_client]
        
        not_found_error = ClientError(
            error_response={
                'Error': {
                    'Code': 'ResourceNotFoundException',
                    'Message': 'Model not found'
                }
            },
            operation_name='GetFoundationModel'
        )
        
        mock_bedrock_client.get_foundation_model.side_effect = not_found_error
        
        client = BedrockClient(self.config)
        is_compatible = client.validate_model_region_compatibility(
            'nonexistent.model'
        )
        
        assert is_compatible is False
    
    @patch('boto3.Session')
    def test_validate_model_region_compatibility_different_region(self, mock_session):
        """Test validation with different region."""
        mock_runtime_client = Mock()
        mock_bedrock_client = Mock()
        mock_temp_bedrock_client = Mock()
        
        # First two calls for initialization, third for temp client
        mock_session.return_value.client.side_effect = [
            mock_runtime_client, 
            mock_bedrock_client,
            mock_temp_bedrock_client
        ]
        
        mock_response = {
            'modelDetails': {
                'modelId': 'anthropic.claude-3-sonnet-20240229-v1:0',
                'modelLifecycle': {'status': 'ACTIVE'}
            }
        }
        
        mock_temp_bedrock_client.get_foundation_model.return_value = mock_response
        
        client = BedrockClient(self.config)
        is_compatible = client.validate_model_region_compatibility(
            'anthropic.claude-3-sonnet-20240229-v1:0',
            region='us-west-2'
        )
        
        assert is_compatible is True
        # Should use temp client for different region
        mock_temp_bedrock_client.get_foundation_model.assert_called_once()
        # Original client should not be called
        mock_bedrock_client.get_foundation_model.assert_not_called()
    
    @patch('boto3.Session')
    def test_get_model_recommendations_general(self, mock_session):
        """Test model recommendations for general use case."""
        mock_runtime_client = Mock()
        mock_bedrock_client = Mock()
        mock_session.return_value.client.side_effect = [mock_runtime_client, mock_bedrock_client]
        
        mock_response = {
            'modelSummaries': [
                {
                    'modelId': 'anthropic.claude-3-sonnet-20240229-v1:0',
                    'modelName': 'Claude 3 Sonnet',
                    'providerName': 'Anthropic',
                    'inputModalities': ['TEXT'],
                    'outputModalities': ['TEXT'],
                    'supportedInferenceTypes': ['ON_DEMAND'],
                    'modelLifecycle': {'status': 'ACTIVE'},
                    'customizationsSupported': [],
                    'inferenceTypesSupported': ['ON_DEMAND']
                },
                {
                    'modelId': 'amazon.titan-text-express-v1',
                    'modelName': 'Titan Text G1 - Express',
                    'providerName': 'Amazon',
                    'inputModalities': ['TEXT'],
                    'outputModalities': ['TEXT'],
                    'supportedInferenceTypes': ['ON_DEMAND'],
                    'modelLifecycle': {'status': 'ACTIVE'},
                    'customizationsSupported': [],
                    'inferenceTypesSupported': ['ON_DEMAND']
                },
                {
                    'modelId': 'ai21.j2-ultra-v1',
                    'modelName': 'Jurassic-2 Ultra',
                    'providerName': 'AI21 Labs',
                    'inputModalities': ['TEXT'],
                    'outputModalities': ['TEXT'],
                    'supportedInferenceTypes': ['ON_DEMAND'],
                    'modelLifecycle': {'status': 'ACTIVE'},
                    'customizationsSupported': [],
                    'inferenceTypesSupported': ['ON_DEMAND']
                }
            ]
        }
        
        mock_bedrock_client.list_foundation_models.return_value = mock_response
        
        client = BedrockClient(self.config)
        recommendations = client.get_model_recommendations("general")
        
        # Should return models, with Anthropic and Amazon preferred
        assert len(recommendations) > 0
        assert all(isinstance(model, ModelInfo) for model in recommendations)
        
        # Claude should be first due to higher scoring
        claude_models = [m for m in recommendations if 'claude' in m.model_id.lower()]
        assert len(claude_models) > 0
    
    @patch('boto3.Session')
    def test_get_model_recommendations_analysis(self, mock_session):
        """Test model recommendations for analysis use case."""
        mock_runtime_client = Mock()
        mock_bedrock_client = Mock()
        mock_session.return_value.client.side_effect = [mock_runtime_client, mock_bedrock_client]
        
        mock_response = {
            'modelSummaries': [
                {
                    'modelId': 'anthropic.claude-3-sonnet-20240229-v1:0',
                    'modelName': 'Claude 3 Sonnet',
                    'providerName': 'Anthropic',
                    'inputModalities': ['TEXT'],
                    'outputModalities': ['TEXT'],
                    'supportedInferenceTypes': ['ON_DEMAND'],
                    'modelLifecycle': {'status': 'ACTIVE'},
                    'customizationsSupported': [],
                    'inferenceTypesSupported': ['ON_DEMAND']
                }
            ]
        }
        
        mock_bedrock_client.list_foundation_models.return_value = mock_response
        
        client = BedrockClient(self.config)
        recommendations = client.get_model_recommendations("analysis")
        
        assert len(recommendations) > 0
        # Should prefer Anthropic models for analysis
        assert all(model.provider_name == 'Anthropic' for model in recommendations)
    
    @patch('boto3.Session')
    def test_get_model_recommendations_filters_inactive(self, mock_session):
        """Test that recommendations filter out inactive models."""
        mock_runtime_client = Mock()
        mock_bedrock_client = Mock()
        mock_session.return_value.client.side_effect = [mock_runtime_client, mock_bedrock_client]
        
        mock_response = {
            'modelSummaries': [
                {
                    'modelId': 'anthropic.claude-3-sonnet-20240229-v1:0',
                    'modelName': 'Claude 3 Sonnet',
                    'providerName': 'Anthropic',
                    'inputModalities': ['TEXT'],
                    'outputModalities': ['TEXT'],
                    'supportedInferenceTypes': ['ON_DEMAND'],
                    'modelLifecycle': {'status': 'ACTIVE'},
                    'customizationsSupported': [],
                    'inferenceTypesSupported': ['ON_DEMAND']
                },
                {
                    'modelId': 'legacy.model-v1',
                    'modelName': 'Legacy Model',
                    'providerName': 'Anthropic',
                    'inputModalities': ['TEXT'],
                    'outputModalities': ['TEXT'],
                    'supportedInferenceTypes': ['ON_DEMAND'],
                    'modelLifecycle': {'status': 'LEGACY'},  # Inactive
                    'customizationsSupported': [],
                    'inferenceTypesSupported': ['ON_DEMAND']
                }
            ]
        }
        
        mock_bedrock_client.list_foundation_models.return_value = mock_response
        
        client = BedrockClient(self.config)
        recommendations = client.get_model_recommendations("general")
        
        # Should only return active models
        assert len(recommendations) == 1
        assert recommendations[0].model_id == 'anthropic.claude-3-sonnet-20240229-v1:0'
    
    @patch('boto3.Session')
    def test_clear_model_cache(self, mock_session):
        """Test clearing the model cache."""
        mock_runtime_client = Mock()
        mock_bedrock_client = Mock()
        mock_session.return_value.client.side_effect = [mock_runtime_client, mock_bedrock_client]
        
        client = BedrockClient(self.config)
        
        # Add something to cache
        client._model_cache['test'] = ['data']
        client._cache_expiry = Mock()
        
        # Clear cache
        client.clear_model_cache()
        
        assert len(client._model_cache) == 0
        assert client._cache_expiry is None
    
    @patch('boto3.Session')
    def test_cache_expiry_logic(self, mock_session):
        """Test cache expiry logic."""
        mock_runtime_client = Mock()
        mock_bedrock_client = Mock()
        mock_session.return_value.client.side_effect = [mock_runtime_client, mock_bedrock_client]
        
        client = BedrockClient(self.config)
        
        # Test with no cache expiry
        assert client._is_cache_valid() is False
        
        # Test with future expiry
        from datetime import datetime, timedelta
        client._cache_expiry = datetime.now() + timedelta(minutes=30)
        assert client._is_cache_valid() is True
        
        # Test with past expiry
        client._cache_expiry = datetime.now() - timedelta(minutes=30)
        assert client._is_cache_valid() is False