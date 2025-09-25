"""
Unit tests for ThreatForest setup wizard.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, call
from datetime import datetime

import pytest
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

from threatforest.setup_wizard import SetupWizard, SetupWizardError, CredentialStatus
from threatforest.config import ThreatForestConfig, BedrockConfig, ValidationResult
# Lazy imports to avoid circular dependencies - will be imported in test methods as needed


class TestSetupWizard:
    """Test cases for SetupWizard class."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.wizard = SetupWizard(self.temp_dir)
    
    def test_wizard_initialization(self):
        """Test setup wizard initialization."""
        assert self.wizard.project_dir == Path(self.temp_dir)
        assert self.wizard.config_manager is not None
        assert self.wizard._aws_credentials_valid is False
        assert self.wizard._available_models == []
        assert self.wizard._selected_config is None
    
    def test_wizard_initialization_default_dir(self):
        """Test setup wizard initialization with default directory."""
        wizard = SetupWizard()
        assert wizard.project_dir == Path.cwd()


class TestCredentialDetection:
    """Test cases for AWS credential detection."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.wizard = SetupWizard(self.temp_dir)
    
    @patch('boto3.Session')
    def test_detect_aws_credentials_success(self, mock_session_class):
        """Test successful AWS credential detection."""
        # Mock successful credential detection
        mock_session = MagicMock()
        mock_credentials = MagicMock()
        mock_credentials.access_key = "test_key"
        mock_credentials.secret_key = "test_secret"
        
        mock_session.get_credentials.return_value = mock_credentials
        
        mock_sts_client = MagicMock()
        mock_sts_client.get_caller_identity.return_value = {
            'Account': '123456789012',
            'Arn': 'arn:aws:iam::123456789012:user/testuser',
            'UserId': 'AIDACKCEVSQ6C2EXAMPLE'
        }
        mock_session.client.return_value = mock_sts_client
        
        mock_session_class.return_value = mock_session
        
        # Test credential detection
        result = self.wizard.detect_aws_credentials()
        
        assert result.is_valid is True
        assert result.account_id == '123456789012'
        assert result.user_arn == 'arn:aws:iam::123456789012:user/testuser'
        assert result.user_id == 'AIDACKCEVSQ6C2EXAMPLE'
        assert self.wizard._aws_credentials_valid is True
    
    @patch('boto3.Session')
    def test_detect_aws_credentials_no_credentials(self, mock_session_class):
        """Test credential detection when no credentials are found."""
        mock_session = MagicMock()
        mock_session.get_credentials.return_value = None
        mock_session_class.return_value = mock_session
        
        result = self.wizard.detect_aws_credentials()
        
        assert result.is_valid is False
        assert result.error_type == "no_credentials"
        assert "No AWS credentials found" in result.message
        assert self.wizard._aws_credentials_valid is False
    
    @patch('boto3.Session')
    def test_detect_aws_credentials_no_credentials_error(self, mock_session_class):
        """Test credential detection with NoCredentialsError."""
        mock_session_class.side_effect = NoCredentialsError()
        
        result = self.wizard.detect_aws_credentials()
        
        assert result.is_valid is False
        assert result.error_type == "no_credentials"
        assert "No AWS credentials configured" in result.message
    
    @patch('boto3.Session')
    def test_detect_aws_credentials_partial_credentials(self, mock_session_class):
        """Test credential detection with partial credentials."""
        mock_session_class.side_effect = PartialCredentialsError(
            provider='env',
            cred_var='AWS_SECRET_ACCESS_KEY'
        )
        
        result = self.wizard.detect_aws_credentials()
        
        assert result.is_valid is False
        assert result.error_type == "partial_credentials"
        assert "Partial AWS credentials" in result.message
    
    @patch('boto3.Session')
    def test_detect_aws_credentials_client_error(self, mock_session_class):
        """Test credential detection with AWS client error."""
        mock_session = MagicMock()
        mock_credentials = MagicMock()
        mock_credentials.access_key = "test_key"
        mock_credentials.secret_key = "test_secret"
        mock_session.get_credentials.return_value = mock_credentials
        
        mock_sts_client = MagicMock()
        mock_sts_client.get_caller_identity.side_effect = ClientError(
            error_response={'Error': {'Code': 'InvalidUserID.NotFound', 'Message': 'Invalid credentials'}},
            operation_name='GetCallerIdentity'
        )
        mock_session.client.return_value = mock_sts_client
        mock_session_class.return_value = mock_session
        
        result = self.wizard.detect_aws_credentials()
        
        assert result.is_valid is False
        assert result.error_type == "credential_error"
        assert "Invalid credentials" in result.message
    
    @patch('threatforest.setup_wizard.os.getenv')
    def test_get_credential_source_environment(self, mock_getenv):
        """Test credential source detection for environment variables."""
        mock_getenv.side_effect = lambda key: {
            'AWS_ACCESS_KEY_ID': 'test_key',
            'AWS_SECRET_ACCESS_KEY': 'test_secret',
            'AWS_PROFILE': None
        }.get(key)
        
        source = self.wizard._get_credential_source()
        assert source == "environment_variables"
    
    @patch('threatforest.setup_wizard.os.getenv')
    def test_get_credential_source_profile(self, mock_getenv):
        """Test credential source detection for AWS profile."""
        mock_getenv.side_effect = lambda key: {
            'AWS_ACCESS_KEY_ID': None,
            'AWS_SECRET_ACCESS_KEY': None,
            'AWS_PROFILE': 'test_profile'
        }.get(key)
        
        source = self.wizard._get_credential_source()
        assert source == "aws_profile_test_profile"
    
    @patch('threatforest.setup_wizard.os.getenv')
    def test_get_credential_source_config_file(self, mock_getenv):
        """Test credential source detection for AWS config file."""
        mock_getenv.return_value = None
        
        source = self.wizard._get_credential_source()
        assert source == "aws_config_file"


class TestBedrockConfiguration:
    """Test cases for Bedrock configuration."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.wizard = SetupWizard(self.temp_dir)
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.IntPrompt.ask')
    def test_prompt_for_region_default(self, mock_int_prompt, mock_print):
        """Test region selection with default choice."""
        mock_int_prompt.return_value = 1  # First option (us-east-1)
        
        region = self.wizard._prompt_for_region()
        
        assert region == "us-east-1"
        mock_int_prompt.assert_called_once()
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.IntPrompt.ask')
    def test_prompt_for_region_custom(self, mock_int_prompt, mock_print):
        """Test region selection with custom region."""
        mock_int_prompt.return_value = 8  # "other" option
        
        with patch('threatforest.setup_wizard.Prompt.ask', return_value='us-gov-west-1'):
            region = self.wizard._prompt_for_region()
        
        assert region == "us-gov-west-1"
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.IntPrompt.ask')
    def test_prompt_for_region_invalid_choice(self, mock_int_prompt, mock_print):
        """Test region selection with invalid choice followed by valid choice."""
        mock_int_prompt.side_effect = [99, 2]  # Invalid, then valid choice
        
        region = self.wizard._prompt_for_region()
        
        assert region == "us-west-2"
        assert mock_int_prompt.call_count == 2
    
    @patch('threatforest.setup_wizard.BedrockClient')
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.IntPrompt.ask')
    @patch('threatforest.setup_wizard.Confirm.ask')
    def test_prompt_for_model_success(self, mock_confirm, mock_int_prompt, mock_print, mock_bedrock_client_class):
        """Test successful model selection."""
        # Create a mock model object without importing the actual class
        mock_model = MagicMock()
        mock_model.model_id = "anthropic.claude-3-sonnet-20240229-v1:0"
        mock_model.model_name = "Claude 3 Sonnet"
        mock_model.provider_name = "Anthropic"
        mock_model.model_lifecycle_status = "ACTIVE"
        mock_model.input_modalities = ["TEXT"]
        mock_model.output_modalities = ["TEXT"]
        
        mock_bedrock_client = MagicMock()
        mock_bedrock_client.list_inference_profiles.side_effect = Exception("No inference profiles")
        mock_bedrock_client.get_model_recommendations.return_value = [mock_model]
        mock_bedrock_client_class.return_value = mock_bedrock_client
        
        mock_confirm.return_value = False  # Don't show setup guidance
        mock_int_prompt.return_value = 1  # First model
        
        model_id = self.wizard._prompt_for_model("us-east-1")
        
        assert model_id == "anthropic.claude-3-sonnet-20240229-v1:0"
        assert len(self.wizard._available_models) == 1
    
    @patch('threatforest.setup_wizard.BedrockClient')
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.IntPrompt.ask')
    @patch('threatforest.setup_wizard.Confirm.ask')
    def test_prompt_for_model_discovery_failure(self, mock_confirm, mock_int_prompt, mock_print, mock_bedrock_client_class):
        """Test model selection when discovery fails."""
        # Create a mock exception class that behaves like BedrockClientError
        class MockBedrockClientError(Exception):
            pass
        MockBedrockClientError.__name__ = "BedrockClientError"
        
        mock_error = MockBedrockClientError("Discovery failed")
        
        # Mock discovery failure
        mock_bedrock_client = MagicMock()
        mock_bedrock_client.list_inference_profiles.side_effect = Exception("No inference profiles")
        mock_bedrock_client.get_model_recommendations.side_effect = mock_error
        mock_bedrock_client_class.return_value = mock_bedrock_client
        
        mock_confirm.return_value = False  # Don't show setup guidance
        mock_int_prompt.return_value = 1  # First fallback model
        
        model_id = self.wizard._prompt_for_model("us-east-1")
        
        assert model_id == "anthropic.claude-3-5-sonnet-20241022-v2:0"  # First fallback model
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.IntPrompt.ask')
    def test_prompt_for_fallback_model_custom(self, mock_int_prompt, mock_print):
        """Test fallback model selection with custom model."""
        mock_int_prompt.return_value = 6  # Custom model option (5 fallback models + 1)
        
        with patch('threatforest.setup_wizard.Prompt.ask', return_value='custom.model.id'):
            model_id = self.wizard._prompt_for_fallback_model()
        
        assert model_id == "custom.model.id"
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.Confirm.ask')
    def test_prompt_for_model_parameters_defaults(self, mock_confirm, mock_print):
        """Test model parameters with default values."""
        mock_confirm.return_value = False  # Don't configure advanced parameters
        
        params = self.wizard._prompt_for_model_parameters()
        
        expected = {
            'temperature': 0.1,
            'max_tokens': 4000,
            'top_p': 0.9
        }
        assert params == expected
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.Confirm.ask')
    @patch('threatforest.setup_wizard.FloatPrompt.ask')
    @patch('threatforest.setup_wizard.IntPrompt.ask')
    def test_prompt_for_model_parameters_custom(self, mock_int_prompt, mock_float_prompt, mock_confirm, mock_print):
        """Test model parameters with custom values."""
        mock_confirm.return_value = True  # Configure advanced parameters
        mock_float_prompt.side_effect = [0.3, 0.8]  # temperature, top_p
        mock_int_prompt.return_value = 8000  # max_tokens
        
        params = self.wizard._prompt_for_model_parameters()
        
        expected = {
            'temperature': 0.3,
            'max_tokens': 8000,
            'top_p': 0.8
        }
        assert params == expected
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.Confirm.ask')
    @patch('threatforest.setup_wizard.Prompt.ask')
    @patch('threatforest.setup_wizard.IntPrompt.ask')
    def test_configure_additional_settings(self, mock_int_prompt, mock_prompt, mock_confirm, mock_print):
        """Test additional settings configuration."""
        mock_confirm.side_effect = [True, True]  # Configure both output and processing
        mock_prompt.side_effect = ["./custom-output", "medium"]  # output dir, severity
        mock_int_prompt.return_value = 6  # max agents
        
        config = self.wizard._configure_additional_settings()
        
        expected = {
            'output': {'directory': './custom-output'},
            'processing': {
                'severity_threshold': 'medium',
                'max_concurrent_agents': 6
            }
        }
        assert config == expected
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.Prompt.ask')
    def test_prompt_for_configuration_scope(self, mock_prompt, mock_print):
        """Test configuration scope selection."""
        mock_prompt.return_value = "user"
        
        scope = self.wizard._prompt_for_configuration_scope()
        
        assert scope == "user"
        mock_prompt.assert_called_once_with(
            "Configuration scope",
            choices=["user", "project"],
            default="project"
        )


class TestConfigurationTesting:
    """Test cases for configuration testing."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.wizard = SetupWizard(self.temp_dir)
    
    @patch('threatforest.setup_wizard.BedrockClient')
    @patch('threatforest.setup_wizard.console.print')
    def test_test_configuration_success(self, mock_print, mock_bedrock_client_class):
        """Test successful configuration testing."""
        # Create test configuration
        config = ThreatForestConfig(
            bedrock=BedrockConfig(
                region="us-east-1",
                model="anthropic.claude-3-sonnet-20240229-v1:0"
            )
        )
        
        # Mock successful validation
        mock_validation_result = ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[],
            tested_components={"aws_credentials": True, "bedrock_config": True},
            validation_time=datetime.now()
        )
        
        with patch.object(self.wizard.config_manager, 'validate_configuration', return_value=mock_validation_result):
            # Mock successful Bedrock connection test
            mock_bedrock_client = MagicMock()
            mock_bedrock_client.test_connection.return_value = True
            mock_bedrock_client_class.return_value = mock_bedrock_client
            
            result = self.wizard.test_configuration(config)
        
        assert result.is_valid is True
        assert len(result.errors) == 0
    
    @patch('threatforest.setup_wizard.BedrockClient')
    @patch('threatforest.setup_wizard.console.print')
    def test_test_configuration_bedrock_failure(self, mock_print, mock_bedrock_client_class):
        """Test configuration testing with Bedrock connection failure."""
        config = ThreatForestConfig(
            bedrock=BedrockConfig(
                region="us-east-1",
                model="anthropic.claude-3-sonnet-20240229-v1:0"
            )
        )
        
        # Mock successful validation but failed Bedrock connection
        mock_validation_result = ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[],
            tested_components={"aws_credentials": True, "bedrock_config": True},
            validation_time=datetime.now()
        )
        
        with patch.object(self.wizard.config_manager, 'validate_configuration', return_value=mock_validation_result):
            # Mock failed Bedrock connection test
            mock_bedrock_client = MagicMock()
            mock_bedrock_client.test_connection.return_value = False
            mock_bedrock_client_class.return_value = mock_bedrock_client
            
            result = self.wizard.test_configuration(config)
        
        assert result.is_valid is False
        assert len(result.errors) == 1
        assert result.errors[0].component == 'bedrock_connectivity'
    
    @patch('threatforest.setup_wizard.BedrockClient')
    @patch('threatforest.setup_wizard.console.print')
    def test_test_configuration_bedrock_error(self, mock_print, mock_bedrock_client_class):
        """Test configuration testing with Bedrock client error."""
        # Create a mock exception class that behaves like BedrockClientError
        class MockBedrockClientError(Exception):
            pass
        MockBedrockClientError.__name__ = "BedrockClientError"
        
        mock_error = MockBedrockClientError("Connection failed")
        
        config = ThreatForestConfig(
            bedrock=BedrockConfig(
                region="us-east-1",
                model="anthropic.claude-3-sonnet-20240229-v1:0"
            )
        )
        
        # Mock successful validation
        mock_validation_result = ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[],
            tested_components={"aws_credentials": True, "bedrock_config": True},
            validation_time=datetime.now()
        )
        
        with patch.object(self.wizard.config_manager, 'validate_configuration', return_value=mock_validation_result):
            # Mock Bedrock client error
            mock_bedrock_client_class.side_effect = mock_error
            
            result = self.wizard.test_configuration(config)
        
        assert result.is_valid is False
        assert len(result.errors) == 1
        assert result.errors[0].component == 'bedrock_connectivity'


class TestConfigurationSaving:
    """Test cases for configuration saving."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.wizard = SetupWizard(self.temp_dir)
    
    def test_save_configuration_project_level(self):
        """Test saving configuration at project level."""
        config = ThreatForestConfig()
        
        with patch.object(self.wizard.config_manager, 'save_config') as mock_save:
            self.wizard.save_configuration(config, "project")
            
            mock_save.assert_called_once_with(config, user_level=False)
    
    def test_save_configuration_user_level(self):
        """Test saving configuration at user level."""
        config = ThreatForestConfig()
        
        with patch.object(self.wizard.config_manager, 'save_config') as mock_save:
            self.wizard.save_configuration(config, "user")
            
            mock_save.assert_called_once_with(config, user_level=True)
    
    def test_save_configuration_error(self):
        """Test configuration saving error handling."""
        config = ThreatForestConfig()
        
        with patch.object(self.wizard.config_manager, 'save_config', side_effect=Exception("Save failed")):
            with pytest.raises(SetupWizardError, match="Failed to save configuration"):
                self.wizard.save_configuration(config, "project")


class TestInteractiveSetup:
    """Test cases for the complete interactive setup workflow."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.wizard = SetupWizard(self.temp_dir)
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.Confirm.ask')
    def test_show_welcome_screen_accept(self, mock_confirm, mock_print):
        """Test welcome screen with user acceptance."""
        mock_confirm.return_value = True
        
        # Should not raise exception
        self.wizard._show_welcome_screen()
        
        mock_confirm.assert_called_once_with("\nReady to begin setup?", default=True)
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.Confirm.ask')
    def test_show_welcome_screen_cancel(self, mock_confirm, mock_print):
        """Test welcome screen with user cancellation."""
        mock_confirm.return_value = False
        
        with pytest.raises(SetupWizardError, match="Setup cancelled by user"):
            self.wizard._show_welcome_screen()
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.Prompt.ask')
    @patch('threatforest.setup_wizard.Confirm.ask')
    def test_handle_credential_setup_retry_success(self, mock_confirm, mock_prompt, mock_print):
        """Test credential setup with successful retry."""
        mock_prompt.return_value = "retry"
        
        # Mock successful credential detection on retry
        mock_credential_status = CredentialStatus(is_valid=True)
        
        with patch.object(self.wizard, 'detect_aws_credentials', return_value=mock_credential_status):
            result = self.wizard._handle_credential_setup()
        
        assert result is True
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.Prompt.ask')
    def test_handle_credential_setup_cancel(self, mock_prompt, mock_print):
        """Test credential setup cancellation."""
        mock_prompt.return_value = "cancel"
        
        result = self.wizard._handle_credential_setup()
        
        assert result is False
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.Prompt.ask')
    @patch('threatforest.setup_wizard.Confirm.ask')
    def test_handle_credential_setup_retry_failure(self, mock_confirm, mock_prompt, mock_print):
        """Test credential setup with failed retry."""
        mock_prompt.return_value = "retry"
        mock_confirm.return_value = False  # Don't try again
        
        # Mock failed credential detection
        mock_credential_status = CredentialStatus(
            is_valid=False,
            message="Still no credentials"
        )
        
        with patch.object(self.wizard, 'detect_aws_credentials', return_value=mock_credential_status):
            result = self.wizard._handle_credential_setup()
        
        assert result is False
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.Confirm.ask')
    def test_handle_validation_errors_continue(self, mock_confirm, mock_print):
        """Test handling validation errors with continue choice."""
        mock_confirm.return_value = True
        
        mock_validation_result = ValidationResult(
            is_valid=False,
            errors=[
                type('ValidationError', (), {
                    'component': 'test',
                    'message': 'Test error',
                    'suggestion': 'Test suggestion'
                })()
            ],
            warnings=[],
            tested_components={},
            validation_time=datetime.now()
        )
        
        result = self.wizard._handle_validation_errors(mock_validation_result)
        
        assert result is True
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.Confirm.ask')
    def test_handle_validation_errors_abort(self, mock_confirm, mock_print):
        """Test handling validation errors with abort choice."""
        mock_confirm.return_value = False
        
        mock_validation_result = ValidationResult(
            is_valid=False,
            errors=[
                type('ValidationError', (), {
                    'component': 'test',
                    'message': 'Test error'
                })()
            ],
            warnings=[],
            tested_components={},
            validation_time=datetime.now()
        )
        
        result = self.wizard._handle_validation_errors(mock_validation_result)
        
        assert result is False
    
    @patch('threatforest.setup_wizard.console.print')
    def test_show_completion_screen(self, mock_print):
        """Test completion screen display."""
        config = ThreatForestConfig(
            bedrock=BedrockConfig(
                region="us-east-1",
                model="anthropic.claude-3-sonnet-20240229-v1:0"
            )
        )
        
        # Should not raise exception
        self.wizard._show_completion_screen(config, "project")
        
        # Verify console.print was called
        mock_print.assert_called()


class TestCredentialStatus:
    """Test cases for CredentialStatus class."""
    
    def test_credential_status_valid(self):
        """Test valid credential status."""
        status = CredentialStatus(
            is_valid=True,
            account_id="123456789012",
            user_arn="arn:aws:iam::123456789012:user/testuser",
            user_id="AIDACKCEVSQ6C2EXAMPLE",
            detection_method="environment_variables"
        )
        
        assert status.is_valid is True
        assert status.account_id == "123456789012"
        assert status.user_arn == "arn:aws:iam::123456789012:user/testuser"
        assert status.user_id == "AIDACKCEVSQ6C2EXAMPLE"
        assert status.detection_method == "environment_variables"
    
    def test_credential_status_invalid(self):
        """Test invalid credential status."""
        status = CredentialStatus(
            is_valid=False,
            error_type="no_credentials",
            message="No AWS credentials found",
            suggestion="Configure AWS credentials",
            detection_method="boto3_session"
        )
        
        assert status.is_valid is False
        assert status.error_type == "no_credentials"
        assert status.message == "No AWS credentials found"
        assert status.suggestion == "Configure AWS credentials"
        assert status.detection_method == "boto3_session"


class TestSetupWizardError:
    """Test cases for SetupWizardError exception."""
    
    def test_setup_wizard_error(self):
        """Test SetupWizardError exception."""
        error = SetupWizardError("Test error message")
        
        assert str(error) == "Test error message"
        assert isinstance(error, Exception)