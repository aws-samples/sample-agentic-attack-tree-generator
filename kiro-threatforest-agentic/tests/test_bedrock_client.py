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
    BedrockClientError
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