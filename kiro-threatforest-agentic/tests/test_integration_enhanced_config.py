"""
Integration tests for enhanced model provider configuration functionality.

Tests the complete workflows for setup wizard, model discovery, configuration validation,
and CLI integration for the enhanced Bedrock configuration features.
"""

import os
import tempfile
import asyncio
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime

import pytest
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from threatforest.setup_wizard import SetupWizard, CredentialStatus
from threatforest.config import ThreatForestConfig, BedrockConfig, ConfigManager, ValidationResult

from tests.fixtures import (
    create_test_project,
    setup_mock_environment,
    cleanup_test_files,
    measure_performance,
    assert_performance_within_limits
)


class TestSetupWizardIntegration:
    """Integration tests for setup wizard workflow."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.wizard = SetupWizard(self.temp_dir)
    
    def teardown_method(self):
        """Clean up test environment."""
        cleanup_test_files(Path(self.temp_dir))
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.Confirm.ask')
    @patch('threatforest.setup_wizard.IntPrompt.ask')
    @patch('threatforest.setup_wizard.Prompt.ask')
    @patch('boto3.Session')
    def test_complete_setup_wizard_workflow_success(self, mock_session_class, mock_prompt, 
                                                   mock_int_prompt, mock_confirm, mock_print):
        """Test complete setup wizard workflow with successful configuration."""
        # Mock AWS credential detection
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
        
        # Mock user interactions
        mock_confirm.side_effect = [
            True,   # Welcome screen - proceed
            False,  # Don't configure advanced parameters
            False,  # Don't configure additional settings - output
            False,  # Don't configure additional settings - processing
            True    # Confirm final configuration
        ]
        
        mock_int_prompt.side_effect = [
            1,  # Select first region (us-east-1)
            1   # Select first model
        ]
        
        mock_prompt.side_effect = [
            "project"  # Configuration scope
        ]
        
        # Mock model discovery
        with patch('threatforest.setup_wizard.BedrockClient') as mock_bedrock_client_class:
            mock_model = MagicMock()
            mock_model.model_id = "anthropic.claude-3-sonnet-20240229-v1:0"
            mock_model.model_name = "Claude 3 Sonnet"
            mock_model.provider_name = "Anthropic"
            mock_model.model_lifecycle_status = "ACTIVE"
            
            mock_bedrock_client = MagicMock()
            mock_bedrock_client.get_model_recommendations.return_value = [mock_model]
            mock_bedrock_client.test_connection.return_value = True
            mock_bedrock_client_class.return_value = mock_bedrock_client
            
            # Mock configuration validation
            with patch.object(self.wizard.config_manager, 'validate_configuration') as mock_validate:
                mock_validation_result = ValidationResult(
                    is_valid=True,
                    errors=[],
                    warnings=[],
                    tested_components={"aws_credentials": True, "bedrock_config": True},
                    validation_time=datetime.now()
                )
                mock_validate.return_value = mock_validation_result
                
                # Mock configuration saving
                with patch.object(self.wizard.config_manager, 'save_config') as mock_save:
                    # Run complete setup workflow
                    config = self.wizard.run_interactive_setup()
                    
                    # Verify configuration was created correctly
                    assert isinstance(config, ThreatForestConfig)
                    assert config.bedrock.region == "us-east-1"
                    assert config.bedrock.model == "anthropic.claude-3-sonnet-20240229-v1:0"
                    assert config.bedrock.temperature == 0.1  # Default value
                    assert config.bedrock.max_tokens == 4000  # Default value
                    assert config.bedrock.top_p == 0.9  # Default value
                    
                    # Verify save was called
                    mock_save.assert_called_once_with(config, user_level=False)  
  
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.Confirm.ask')
    @patch('threatforest.setup_wizard.IntPrompt.ask')
    @patch('threatforest.setup_wizard.FloatPrompt.ask')
    @patch('threatforest.setup_wizard.Prompt.ask')
    @patch('boto3.Session')
    def test_setup_wizard_with_advanced_parameters(self, mock_session_class, mock_prompt,
                                                  mock_float_prompt, mock_int_prompt, 
                                                  mock_confirm, mock_print):
        """Test setup wizard workflow with advanced parameter configuration."""
        # Mock AWS credential detection
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
        
        # Mock user interactions for advanced configuration
        mock_confirm.side_effect = [
            True,   # Welcome screen - proceed
            True,   # Configure advanced parameters
            True,   # Configure additional settings - output
            True,   # Configure additional settings - processing
            True    # Confirm final configuration
        ]
        
        mock_int_prompt.side_effect = [
            2,      # Select second region (us-west-2)
            1,      # Select first model
            8000,   # max_tokens
            6       # max_concurrent_agents
        ]
        
        mock_float_prompt.side_effect = [
            0.7,    # temperature
            0.85    # top_p
        ]
        
        mock_prompt.side_effect = [
            "./custom-output",  # output directory
            "medium",          # severity threshold
            "user"             # configuration scope
        ]
        
        # Mock model discovery
        with patch('threatforest.setup_wizard.BedrockClient') as mock_bedrock_client_class:
            mock_model = MagicMock()
            mock_model.model_id = "anthropic.claude-3-haiku-20240307-v1:0"
            mock_model.model_name = "Claude 3 Haiku"
            mock_model.provider_name = "Anthropic"
            mock_model.model_lifecycle_status = "ACTIVE"
            
            mock_bedrock_client = MagicMock()
            mock_bedrock_client.get_model_recommendations.return_value = [mock_model]
            mock_bedrock_client.test_connection.return_value = True
            mock_bedrock_client_class.return_value = mock_bedrock_client
            
            # Mock configuration validation
            with patch.object(self.wizard.config_manager, 'validate_configuration') as mock_validate:
                mock_validation_result = ValidationResult(
                    is_valid=True,
                    errors=[],
                    warnings=[],
                    tested_components={"aws_credentials": True, "bedrock_config": True},
                    validation_time=datetime.now()
                )
                mock_validate.return_value = mock_validation_result
                
                # Mock configuration saving
                with patch.object(self.wizard.config_manager, 'save_config') as mock_save:
                    # Run complete setup workflow
                    config = self.wizard.run_interactive_setup()
                    
                    # Verify advanced configuration was applied
                    assert config.bedrock.region == "us-west-2"
                    assert config.bedrock.model == "anthropic.claude-3-haiku-20240307-v1:0"
                    assert config.bedrock.temperature == 0.7
                    assert config.bedrock.max_tokens == 8000
                    assert config.bedrock.top_p == 0.85
                    assert config.output.directory == "./custom-output"
                    assert config.processing.severity_threshold == "medium"
                    assert config.processing.max_concurrent_agents == 6
                    
                    # Verify save was called with user level
                    mock_save.assert_called_once_with(config, user_level=True)
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.Confirm.ask')
    @patch('threatforest.setup_wizard.Prompt.ask')
    @patch('boto3.Session')
    def test_setup_wizard_credential_failure_recovery(self, mock_session_class, mock_prompt,
                                                     mock_confirm, mock_print):
        """Test setup wizard recovery from credential failures."""
        # Mock initial credential failure
        mock_session_class.side_effect = [
            NoCredentialsError(),  # First attempt fails
            MagicMock()           # Second attempt succeeds
        ]
        
        # Mock successful second attempt
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
        
        # Update the side_effect to return the mock_session on second call
        mock_session_class.side_effect = [NoCredentialsError(), mock_session]
        
        # Mock user interactions
        mock_confirm.side_effect = [
            True,   # Welcome screen - proceed
            True,   # Try credential setup again after failure
            False,  # Don't configure advanced parameters
            False,  # Don't configure additional settings
            True    # Confirm final configuration
        ]
        
        mock_prompt.side_effect = [
            "retry",   # Retry credential setup
            "project"  # Configuration scope
        ]
        
        # Mock the rest of the setup process
        with patch('threatforest.setup_wizard.IntPrompt.ask') as mock_int_prompt:
            mock_int_prompt.side_effect = [1, 1]  # Region and model selection
            
            with patch('threatforest.setup_wizard.BedrockClient') as mock_bedrock_client_class:
                mock_model = MagicMock()
                mock_model.model_id = "anthropic.claude-3-sonnet-20240229-v1:0"
                mock_model.model_name = "Claude 3 Sonnet"
                mock_model.provider_name = "Anthropic"
                mock_model.model_lifecycle_status = "ACTIVE"
                
                mock_bedrock_client = MagicMock()
                mock_bedrock_client.get_model_recommendations.return_value = [mock_model]
                mock_bedrock_client.test_connection.return_value = True
                mock_bedrock_client_class.return_value = mock_bedrock_client
                
                # Mock configuration validation and saving
                with patch.object(self.wizard.config_manager, 'validate_configuration') as mock_validate, \
                     patch.object(self.wizard.config_manager, 'save_config') as mock_save:
                    
                    mock_validation_result = ValidationResult(
                        is_valid=True,
                        errors=[],
                        warnings=[],
                        tested_components={"aws_credentials": True, "bedrock_config": True},
                        validation_time=datetime.now()
                    )
                    mock_validate.return_value = mock_validation_result
                    
                    # Run setup workflow - should recover from initial failure
                    config = self.wizard.run_interactive_setup()
                    
                    # Verify configuration was created successfully
                    assert isinstance(config, ThreatForestConfig)
                    assert config.bedrock.region == "us-east-1"
                    assert config.bedrock.model == "anthropic.claude-3-sonnet-20240229-v1:0"
                    
                    # Verify save was called
                    mock_save.assert_called_once()
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.Confirm.ask')
    def test_setup_wizard_user_cancellation(self, mock_confirm, mock_print):
        """Test setup wizard handles user cancellation gracefully."""
        # Mock user cancellation at welcome screen
        mock_confirm.return_value = False
        
        # Should raise SetupWizardError
        from threatforest.setup_wizard import SetupWizardError
        with pytest.raises(SetupWizardError, match="Setup cancelled by user"):
            self.wizard.run_interactive_setup()
    
    @patch('threatforest.setup_wizard.console.print')
    @patch('threatforest.setup_wizard.Confirm.ask')
    @patch('threatforest.setup_wizard.IntPrompt.ask')
    @patch('threatforest.setup_wizard.Prompt.ask')
    @patch('boto3.Session')
    def test_setup_wizard_validation_failure_handling(self, mock_session_class, mock_prompt,
                                                      mock_int_prompt, mock_confirm, mock_print):
        """Test setup wizard handles configuration validation failures."""
        # Mock AWS credential detection
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
        
        # Mock user interactions
        mock_confirm.side_effect = [
            True,   # Welcome screen - proceed
            False,  # Don't configure advanced parameters
            False,  # Don't configure additional settings
            True    # Continue despite validation errors
        ]
        
        mock_int_prompt.side_effect = [1, 1]  # Region and model selection
        mock_prompt.return_value = "project"  # Configuration scope
        
        # Mock model discovery
        with patch('threatforest.setup_wizard.BedrockClient') as mock_bedrock_client_class:
            mock_model = MagicMock()
            mock_model.model_id = "anthropic.claude-3-sonnet-20240229-v1:0"
            mock_model.model_name = "Claude 3 Sonnet"
            mock_model.provider_name = "Anthropic"
            mock_model.model_lifecycle_status = "ACTIVE"
            
            mock_bedrock_client = MagicMock()
            mock_bedrock_client.get_model_recommendations.return_value = [mock_model]
            mock_bedrock_client.test_connection.return_value = False  # Connection fails
            mock_bedrock_client_class.return_value = mock_bedrock_client
            
            # Mock configuration validation with errors
            with patch.object(self.wizard.config_manager, 'validate_configuration') as mock_validate:
                from threatforest.config import ValidationError
                mock_validation_result = ValidationResult(
                    is_valid=False,
                    errors=[ValidationError(
                        component="bedrock_connectivity",
                        error_type="connection_failed",
                        message="Failed to connect to Bedrock service",
                        suggestion="Check network connectivity and AWS credentials"
                    )],
                    warnings=[],
                    tested_components={"aws_credentials": True, "bedrock_config": False},
                    validation_time=datetime.now()
                )
                mock_validate.return_value = mock_validation_result
                
                # Mock configuration saving
                with patch.object(self.wizard.config_manager, 'save_config') as mock_save:
                    # Run setup workflow - should handle validation errors
                    config = self.wizard.run_interactive_setup()
                    
                    # Verify configuration was still created and saved
                    assert isinstance(config, ThreatForestConfig)
                    mock_save.assert_called_once()


class TestModelDiscoveryIntegration:
    """Integration tests for model discovery and selection flows."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test environment."""
        cleanup_test_files(Path(self.temp_dir))
    
    @patch('boto3.Session')
    def test_model_discovery_with_real_bedrock_client(self, mock_session_class):
        """Test model discovery using BedrockClient with mocked AWS calls."""
        # Import BedrockClient locally to avoid circular imports
        from threatforest.utils.bedrock_client import BedrockClient
        
        # Mock AWS session and Bedrock client
        mock_session = MagicMock()
        mock_bedrock_client = MagicMock()
        
        # Mock list_foundation_models response
        mock_models_response = {
            'modelSummaries': [
                {
                    'modelId': 'anthropic.claude-3-sonnet-20240229-v1:0',
                    'modelName': 'Claude 3 Sonnet',
                    'providerName': 'Anthropic',
                    'modelLifecycleStatus': 'ACTIVE',
                    'inputModalities': ['TEXT'],
                    'outputModalities': ['TEXT'],
                    'responseStreamingSupported': True,
                    'customizationsSupported': []
                },
                {
                    'modelId': 'anthropic.claude-3-haiku-20240307-v1:0',
                    'modelName': 'Claude 3 Haiku',
                    'providerName': 'Anthropic',
                    'modelLifecycleStatus': 'ACTIVE',
                    'inputModalities': ['TEXT'],
                    'outputModalities': ['TEXT'],
                    'responseStreamingSupported': True,
                    'customizationsSupported': []
                }
            ]
        }
        
        mock_bedrock_client.list_foundation_models.return_value = mock_models_response
        mock_session.client.return_value = mock_bedrock_client
        mock_session_class.return_value = mock_session
        
        # Test model discovery
        bedrock_client = BedrockClient(region="us-east-1")
        models = bedrock_client.list_available_models()
        
        # Verify models were discovered
        assert len(models) == 2
        assert models[0].model_id == 'anthropic.claude-3-sonnet-20240229-v1:0'
        assert models[0].model_name == 'Claude 3 Sonnet'
        assert models[0].provider_name == 'Anthropic'
        assert models[1].model_id == 'anthropic.claude-3-haiku-20240307-v1:0'
        assert models[1].model_name == 'Claude 3 Haiku'
        assert models[1].provider_name == 'Anthropic'
    
    @patch('boto3.Session')
    def test_model_region_compatibility_validation(self, mock_session_class):
        """Test model region compatibility validation."""
        # Import BedrockClient locally to avoid circular imports
        from threatforest.utils.bedrock_client import BedrockClient
        
        # Mock AWS session and Bedrock client
        mock_session = MagicMock()
        mock_bedrock_client = MagicMock()
        
        # Mock successful model validation
        mock_bedrock_client.list_foundation_models.return_value = {
            'modelSummaries': [
                {
                    'modelId': 'anthropic.claude-3-sonnet-20240229-v1:0',
                    'modelName': 'Claude 3 Sonnet',
                    'providerName': 'Anthropic',
                    'modelLifecycleStatus': 'ACTIVE'
                }
            ]
        }
        
        mock_session.client.return_value = mock_bedrock_client
        mock_session_class.return_value = mock_session
        
        # Test model region compatibility
        bedrock_client = BedrockClient(region="us-east-1")
        
        # Test valid model
        is_compatible = bedrock_client.validate_model_region_compatibility(
            "anthropic.claude-3-sonnet-20240229-v1:0", "us-east-1"
        )
        assert is_compatible is True
        
        # Test invalid model (not in list)
        is_compatible = bedrock_client.validate_model_region_compatibility(
            "invalid.model.id", "us-east-1"
        )
        assert is_compatible is False
    
    @patch('boto3.Session')
    def test_model_recommendations_by_use_case(self, mock_session_class):
        """Test model recommendations based on use case."""
        # Import BedrockClient locally to avoid circular imports
        from threatforest.utils.bedrock_client import BedrockClient
        
        # Mock AWS session and Bedrock client
        mock_session = MagicMock()
        mock_bedrock_client = MagicMock()
        
        # Mock comprehensive model list
        mock_models_response = {
            'modelSummaries': [
                {
                    'modelId': 'anthropic.claude-3-sonnet-20240229-v1:0',
                    'modelName': 'Claude 3 Sonnet',
                    'providerName': 'Anthropic',
                    'modelLifecycleStatus': 'ACTIVE'
                },
                {
                    'modelId': 'anthropic.claude-3-haiku-20240307-v1:0',
                    'modelName': 'Claude 3 Haiku',
                    'providerName': 'Anthropic',
                    'modelLifecycleStatus': 'ACTIVE'
                },
                {
                    'modelId': 'amazon.titan-text-express-v1',
                    'modelName': 'Titan Text G1 - Express',
                    'providerName': 'Amazon',
                    'modelLifecycleStatus': 'ACTIVE'
                }
            ]
        }
        
        mock_bedrock_client.list_foundation_models.return_value = mock_models_response
        mock_session.client.return_value = mock_bedrock_client
        mock_session_class.return_value = mock_session
        
        # Test model recommendations
        bedrock_client = BedrockClient(region="us-east-1")
        
        # Test general use case
        recommendations = bedrock_client.get_model_recommendations("general")
        assert len(recommendations) > 0
        
        # Test threat modeling use case
        recommendations = bedrock_client.get_model_recommendations("threat_modeling")
        assert len(recommendations) > 0
        
        # Verify Claude models are prioritized for threat modeling
        claude_models = [m for m in recommendations if "claude" in m.model_id.lower()]
        assert len(claude_models) > 0
    
    @patch('boto3.Session')
    def test_model_discovery_error_handling(self, mock_session_class):
        """Test model discovery error handling."""
        # Import BedrockClient and BedrockClientError locally to avoid circular imports
        from threatforest.utils.bedrock_client import BedrockClient, BedrockClientError
        
        # Mock AWS session with client error
        mock_session = MagicMock()
        mock_bedrock_client = MagicMock()
        
        # Mock Bedrock API error
        mock_bedrock_client.list_foundation_models.side_effect = ClientError(
            error_response={
                'Error': {
                    'Code': 'AccessDeniedException',
                    'Message': 'User is not authorized to perform: bedrock:ListFoundationModels'
                }
            },
            operation_name='ListFoundationModels'
        )
        
        mock_session.client.return_value = mock_bedrock_client
        mock_session_class.return_value = mock_session
        
        # Test error handling
        bedrock_client = BedrockClient(region="us-east-1")
        
        with pytest.raises(BedrockClientError, match="Failed to list available models"):
            bedrock_client.list_available_models()
    
    def test_model_caching_functionality(self):
        """Test model information caching."""
        # Import BedrockClient locally to avoid circular imports
        from threatforest.utils.bedrock_client import BedrockClient
        
        with patch('boto3.Session') as mock_session_class:
            # Mock AWS session and Bedrock client
            mock_session = MagicMock()
            mock_bedrock_client = MagicMock()
            
            mock_models_response = {
                'modelSummaries': [
                    {
                        'modelId': 'anthropic.claude-3-sonnet-20240229-v1:0',
                        'modelName': 'Claude 3 Sonnet',
                        'providerName': 'Anthropic',
                        'modelLifecycleStatus': 'ACTIVE'
                    }
                ]
            }
            
            mock_bedrock_client.list_foundation_models.return_value = mock_models_response
            mock_session.client.return_value = mock_bedrock_client
            mock_session_class.return_value = mock_session
            
            # Test caching
            bedrock_client = BedrockClient(region="us-east-1")
            
            # First call should hit the API
            models1 = bedrock_client.list_available_models()
            assert len(models1) == 1
            
            # Second call should use cache
            models2 = bedrock_client.list_available_models()
            assert len(models2) == 1
            
            # Verify API was only called once due to caching
            mock_bedrock_client.list_foundation_models.assert_called_once()


class TestConfigurationValidationIntegration:
    """Integration tests for configuration validation scenarios."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_manager = ConfigManager(self.temp_dir)
    
    def teardown_method(self):
        """Clean up test environment."""
        cleanup_test_files(Path(self.temp_dir))
    
    @patch('boto3.Session')
    def test_complete_configuration_validation_success(self, mock_session_class):
        """Test complete configuration validation with all components passing."""
        # Mock AWS session for credential validation
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
        
        # Mock Bedrock client for connectivity test
        with patch('threatforest.config.BedrockClient') as mock_bedrock_client_class:
            mock_bedrock_client = MagicMock()
            mock_bedrock_client.test_connection.return_value = True
            mock_bedrock_client_class.return_value = mock_bedrock_client
            
            # Load and validate configuration
            config = self.config_manager.load_config()
            result = self.config_manager.validate_configuration(config)
            
            # Verify successful validation
            assert result.is_valid is True
            assert len(result.errors) == 0
            assert result.tested_components["aws_credentials"] is True
            assert result.tested_components["bedrock_config"] is True
            assert result.tested_components["bedrock_connectivity"] is True
    
    @patch('boto3.Session')
    def test_configuration_validation_with_credential_errors(self, mock_session_class):
        """Test configuration validation with AWS credential errors."""
        # Mock credential failure
        mock_session_class.side_effect = NoCredentialsError()
        
        # Load and validate configuration
        config = self.config_manager.load_config()
        result = self.config_manager.validate_configuration(config)
        
        # Verify validation failure
        assert result.is_valid is False
        assert len(result.errors) > 0
        assert any(error.component == "aws_credentials" for error in result.errors)
        assert any(error.error_type == "no_credentials" for error in result.errors)
        assert result.tested_components["aws_credentials"] is False
    
    def test_configuration_validation_with_invalid_parameters(self):
        """Test configuration validation with invalid Bedrock parameters."""
        # Create configuration with invalid parameters
        config = ThreatForestConfig(
            bedrock=BedrockConfig(
                region="us-east-1",
                model="",  # Invalid empty model
                timeout_seconds=5  # Very low timeout
            )
        )
        
        # Bypass Pydantic validation by setting invalid values directly
        config.bedrock.__dict__['temperature'] = 1.5  # Invalid temperature
        config.bedrock.__dict__['max_tokens'] = -100   # Invalid max_tokens
        config.bedrock.__dict__['top_p'] = 2.0         # Invalid top_p
        
        # Validate configuration
        result = self.config_manager._validate_bedrock_configuration(config.bedrock)
        
        # Verify validation errors
        assert result["is_valid"] is False
        assert len(result["errors"]) > 0
        
        # Check for specific error types
        error_types = [error["error_type"] for error in result["errors"]]
        assert "invalid_model" in error_types
        assert "invalid_temperature" in error_types
        assert "invalid_max_tokens" in error_types
        assert "invalid_top_p" in error_types
    
    @patch('boto3.Session')
    def test_configuration_validation_with_connectivity_failure(self, mock_session_class):
        """Test configuration validation with Bedrock connectivity failure."""
        # Mock successful AWS credentials
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
        
        # Mock Bedrock client connectivity failure
        with patch('threatforest.config.BedrockClient') as mock_bedrock_client_class:
            mock_bedrock_client = MagicMock()
            mock_bedrock_client.test_connection.return_value = False
            mock_bedrock_client_class.return_value = mock_bedrock_client
            
            # Load and validate configuration
            config = self.config_manager.load_config()
            result = self.config_manager.validate_configuration(config)
            
            # Verify validation failure due to connectivity
            assert result.is_valid is False
            assert len(result.errors) > 0
            assert any(error.component == "bedrock_connectivity" for error in result.errors)
            assert result.tested_components["bedrock_connectivity"] is False
    
    def test_configuration_validation_with_warnings(self):
        """Test configuration validation with warnings but no errors."""
        # Create configuration with suboptimal but valid settings
        config = ThreatForestConfig(
            bedrock=BedrockConfig(
                region="ap-south-1",  # Less common region
                model="anthropic.claude-3-sonnet-20240229-v1:0",
                timeout_seconds=15,   # Low timeout
                max_tokens=95000      # High max tokens
            )
        )
        
        # Validate Bedrock configuration
        result = self.config_manager._validate_bedrock_configuration(config.bedrock)
        
        # Verify warnings are generated
        assert result["is_valid"] is True  # No errors, just warnings
        assert len(result["warnings"]) > 0
        
        # Check for specific warning types
        warning_types = [warning["error_type"] for warning in result["warnings"]]
        assert "low_timeout" in warning_types
    
    def test_enhanced_parameter_validation(self):
        """Test validation of enhanced Bedrock parameters."""
        # Test valid enhanced parameters
        config = BedrockConfig(
            temperature=0.5,
            max_tokens=6000,
            top_p=0.8,
            custom_parameters={"stop_sequences": ["Human:", "Assistant:"]},
            validation_status="valid"
        )
        
        result = self.config_manager._validate_bedrock_configuration(config)
        assert result["is_valid"] is True
        
        # Test edge case values
        config = BedrockConfig(
            temperature=0.0,  # Minimum valid
            max_tokens=1,     # Minimum valid
            top_p=1.0         # Maximum valid
        )
        
        result = self.config_manager._validate_bedrock_configuration(config)
        assert result["is_valid"] is True


class TestCLIIntegrationWithEnhancedConfig:
    """Integration tests for CLI commands with enhanced configuration features."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test environment."""
        cleanup_test_files(Path(self.temp_dir))
    
    def test_cli_status_with_enhanced_validation(self):
        """Test CLI status command with enhanced validation features."""
        # Import CLI locally to avoid circular imports
        from threatforest.cli import cli_app
        
        with patch('threatforest.cli.cli_app.validate_aws_credentials') as mock_validate_aws, \
             patch('threatforest.cli.cli_app.config_manager.validate_configuration') as mock_validate_config:
            
            # Mock AWS credentials validation
            mock_validate_aws.return_value = True
            
            # Mock enhanced configuration validation
            mock_validation = MagicMock()
            mock_validation.is_valid = True
            mock_validation.errors = []
            mock_validation.warnings = []
            mock_validation.tested_components = {
                "aws_credentials": True,
                "bedrock_config": True,
                "bedrock_connectivity": True
            }
            mock_validate_config.return_value = mock_validation
            
            # Load configuration
            config = cli_app.load_config(validate=False)
            
            # Test validation
            result = cli_app._validate_loaded_configuration()
            
            # Verify enhanced validation was performed
            assert result.is_valid is True
            assert result.tested_components["aws_credentials"] is True
            assert result.tested_components["bedrock_config"] is True
            assert result.tested_components["bedrock_connectivity"] is True
    
    def test_cli_analyze_with_validation_enabled(self):
        """Test CLI analyze command with configuration validation enabled."""
        # Import CLI locally to avoid circular imports
        from threatforest.cli import cli_app
        
        with patch('threatforest.cli.cli_app.validate_aws_credentials') as mock_validate_aws, \
             patch('threatforest.cli.cli_app.config_manager.validate_configuration') as mock_validate_config:
            
            # Mock AWS credentials validation
            mock_validate_aws.return_value = True
            
            # Mock successful configuration validation
            mock_validation = MagicMock()
            mock_validation.is_valid = True
            mock_validation.errors = []
            mock_validation.warnings = []
            mock_validation.tested_components = {"aws_credentials": True, "bedrock_config": True}
            mock_validate_config.return_value = mock_validation
            
            # Test loading configuration with validation enabled
            config = cli_app.load_config(validate=True)
            
            # Verify configuration was loaded and validated
            assert config is not None
            assert cli_app.config is not None
            mock_validate_config.assert_called_once()
    
    def test_cli_analyze_skip_validation(self):
        """Test CLI analyze command with validation skipped."""
        # Import CLI locally to avoid circular imports
        from threatforest.cli import cli_app
        
        with patch('threatforest.cli.cli_app.validate_aws_credentials') as mock_validate_aws, \
             patch('threatforest.cli.cli_app.config_manager.validate_configuration') as mock_validate_config:
            
            # Mock AWS credentials validation
            mock_validate_aws.return_value = True
            
            # Test loading configuration with validation disabled
            config = cli_app.load_config(validate=False)
            
            # Verify configuration was loaded without validation
            assert config is not None
            assert cli_app.config is not None
            mock_validate_config.assert_not_called()
    
    def test_cli_configuration_error_handling(self):
        """Test CLI error handling for configuration issues."""
        # Import CLI locally to avoid circular imports
        from threatforest.cli import cli_app
        
        # Test with invalid configuration directory
        with patch.object(cli_app.config_manager, 'load_config', side_effect=Exception("Config error")):
            # Should handle error gracefully
            with patch('sys.exit') as mock_exit:
                cli_app.load_config()
                mock_exit.assert_called_with(1)


class TestPerformanceAndStressScenarios:
    """Performance and stress tests for enhanced configuration features."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test environment."""
        cleanup_test_files(Path(self.temp_dir))
    
    def test_setup_wizard_performance(self):
        """Test setup wizard performance under normal conditions."""
        wizard = SetupWizard(self.temp_dir)
        
        # Mock all external dependencies for performance testing
        with patch('boto3.Session') as mock_session_class, \
             patch('threatforest.setup_wizard.BedrockClient') as mock_bedrock_client_class, \
             patch('threatforest.setup_wizard.console.print'), \
             patch('threatforest.setup_wizard.Confirm.ask', return_value=False), \
             patch('threatforest.setup_wizard.IntPrompt.ask', return_value=1), \
             patch('threatforest.setup_wizard.Prompt.ask', return_value="project"):
            
            # Mock AWS session
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
            
            # Mock Bedrock client
            mock_model = MagicMock()
            mock_model.model_id = "anthropic.claude-3-sonnet-20240229-v1:0"
            mock_model.model_name = "Claude 3 Sonnet"
            mock_model.provider_name = "Anthropic"
            mock_model.model_lifecycle_status = "ACTIVE"
            
            mock_bedrock_client = MagicMock()
            mock_bedrock_client.get_model_recommendations.return_value = [mock_model]
            mock_bedrock_client.test_connection.return_value = True
            mock_bedrock_client_class.return_value = mock_bedrock_client
            
            # Mock validation and saving
            with patch.object(wizard.config_manager, 'validate_configuration') as mock_validate, \
                 patch.object(wizard.config_manager, 'save_config') as mock_save:
                
                mock_validation_result = ValidationResult(
                    is_valid=True,
                    errors=[],
                    warnings=[],
                    tested_components={"aws_credentials": True, "bedrock_config": True},
                    validation_time=datetime.now()
                )
                mock_validate.return_value = mock_validation_result
                
                # Measure performance
                metrics = measure_performance(
                    wizard.detect_aws_credentials
                )
                
                # Verify performance is within acceptable limits
                assert_performance_within_limits(
                    metrics,
                    max_execution_time=2.0,  # 2 seconds for credential detection
                    max_memory_mb=50.0       # 50MB memory limit
                )
                
                assert metrics["success"] is True
    
    def test_model_discovery_performance(self):
        """Test model discovery performance with large model lists."""
        # Import BedrockClient locally to avoid circular imports
        from threatforest.utils.bedrock_client import BedrockClient
        
        with patch('boto3.Session') as mock_session_class:
            # Mock large model list (simulate real Bedrock response)
            large_model_list = []
            for i in range(50):  # Simulate 50 models
                large_model_list.append({
                    'modelId': f'test.model.{i}',
                    'modelName': f'Test Model {i}',
                    'providerName': 'TestProvider',
                    'modelLifecycleStatus': 'ACTIVE'
                })
            
            mock_session = MagicMock()
            mock_bedrock_client = MagicMock()
            mock_bedrock_client.list_foundation_models.return_value = {
                'modelSummaries': large_model_list
            }
            mock_session.client.return_value = mock_bedrock_client
            mock_session_class.return_value = mock_session
            
            # Test performance with large model list
            bedrock_client = BedrockClient(region="us-east-1")
            
            metrics = measure_performance(
                bedrock_client.list_available_models
            )
            
            # Verify performance is acceptable
            assert_performance_within_limits(
                metrics,
                max_execution_time=5.0,  # 5 seconds for large model list
                max_memory_mb=100.0      # 100MB memory limit
            )
            
            assert metrics["success"] is True
            assert len(metrics["result"]) == 50
    
    def test_configuration_validation_performance(self):
        """Test configuration validation performance."""
        config_manager = ConfigManager(self.temp_dir)
        
        # Mock all external dependencies
        with patch('boto3.Session') as mock_session_class, \
             patch('threatforest.config.BedrockClient') as mock_bedrock_client_class:
            
            # Mock AWS session
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
            
            # Mock Bedrock client
            mock_bedrock_client = MagicMock()
            mock_bedrock_client.test_connection.return_value = True
            mock_bedrock_client_class.return_value = mock_bedrock_client
            
            # Load configuration
            config = config_manager.load_config()
            
            # Measure validation performance
            metrics = measure_performance(
                config_manager.validate_configuration,
                config
            )
            
            # Verify performance is acceptable
            assert_performance_within_limits(
                metrics,
                max_execution_time=3.0,  # 3 seconds for full validation
                max_memory_mb=75.0       # 75MB memory limit
            )
            
            assert metrics["success"] is True
            assert metrics["result"].is_valid is True
    
    def test_concurrent_validation_scenarios(self):
        """Test concurrent configuration validation scenarios."""
        config_manager = ConfigManager(self.temp_dir)
        
        # Mock all external dependencies
        with patch('boto3.Session') as mock_session_class, \
             patch('threatforest.config.BedrockClient') as mock_bedrock_client_class:
            
            # Mock AWS session
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
            
            # Mock Bedrock client
            mock_bedrock_client = MagicMock()
            mock_bedrock_client.test_connection.return_value = True
            mock_bedrock_client_class.return_value = mock_bedrock_client
            
            # Load configuration
            config = config_manager.load_config()
            
            # Test concurrent validation calls
            async def run_concurrent_validations():
                tasks = []
                for _ in range(5):  # 5 concurrent validations
                    task = asyncio.create_task(
                        asyncio.to_thread(config_manager.validate_configuration, config)
                    )
                    tasks.append(task)
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                return results
            
            # Run concurrent validations
            results = asyncio.run(run_concurrent_validations())
            
            # Verify all validations completed successfully
            assert len(results) == 5
            for result in results:
                assert not isinstance(result, Exception)
                assert result.is_valid is True


class TestErrorRecoveryScenarios:
    """Test error recovery and resilience scenarios."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test environment."""
        cleanup_test_files(Path(self.temp_dir))
    
    def test_network_failure_recovery(self):
        """Test recovery from network failures during setup."""
        wizard = SetupWizard(self.temp_dir)
        
        # Mock network failure followed by success
        with patch('boto3.Session') as mock_session_class:
            # First call fails with network error
            # Second call succeeds
            mock_session_class.side_effect = [
                ClientError(
                    error_response={'Error': {'Code': 'NetworkError', 'Message': 'Network timeout'}},
                    operation_name='GetCallerIdentity'
                ),
                MagicMock()  # Success on retry
            ]
            
            # Mock successful second attempt
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
            
            # Update side_effect to return success on second call
            mock_session_class.side_effect = [
                ClientError(
                    error_response={'Error': {'Code': 'NetworkError', 'Message': 'Network timeout'}},
                    operation_name='GetCallerIdentity'
                ),
                mock_session
            ]
            
            # First attempt should fail
            result1 = wizard.detect_aws_credentials()
            assert result1.is_valid is False
            assert result1.error_type == "credential_error"
            
            # Second attempt should succeed
            result2 = wizard.detect_aws_credentials()
            assert result2.is_valid is True
            assert result2.account_id == '123456789012'
    
    def test_partial_configuration_recovery(self):
        """Test recovery from partial configuration failures."""
        config_manager = ConfigManager(self.temp_dir)
        
        # Create configuration with some invalid values
        config = ThreatForestConfig(
            bedrock=BedrockConfig(
                region="us-east-1",
                model="anthropic.claude-3-sonnet-20240229-v1:0",
                timeout_seconds=300
            )
        )
        
        # Mock partial validation failure
        with patch('boto3.Session') as mock_session_class, \
             patch('threatforest.config.BedrockClient') as mock_bedrock_client_class:
            
            # Mock successful AWS credentials
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
            
            # Mock Bedrock client failure
            from threatforest.utils.bedrock_client import BedrockClientError
            mock_bedrock_client_class.side_effect = BedrockClientError("Connection failed")
            
            # Validate configuration
            result = config_manager.validate_configuration(config)
            
            # Should have partial success
            assert result.is_valid is False  # Overall failure due to connectivity
            assert result.tested_components["aws_credentials"] is True  # This succeeded
            assert result.tested_components["bedrock_connectivity"] is False  # This failed
            
            # Should have specific error about connectivity
            connectivity_errors = [
                error for error in result.errors 
                if error.component == "bedrock_connectivity"
            ]
            assert len(connectivity_errors) > 0
    
    def test_configuration_corruption_recovery(self):
        """Test recovery from corrupted configuration files."""
        config_manager = ConfigManager(self.temp_dir)
        
        # Create corrupted configuration file
        config_file = Path(self.temp_dir) / ".tf" / "config.yaml"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text("invalid: yaml: content: [")
        
        # Should handle corrupted file gracefully
        with pytest.raises(ValueError, match="Error loading config file"):
            config_manager._load_yaml_file(config_file)
        
        # Should fall back to defaults when loading configuration
        config = config_manager.load_config()
        assert isinstance(config, ThreatForestConfig)
        assert config.bedrock.region == "us-east-1"  # Default value
    
    def test_permission_error_handling(self):
        """Test handling of permission errors during configuration operations."""
        # Create read-only directory to simulate permission errors
        readonly_dir = Path(self.temp_dir) / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o444)  # Read-only
        
        try:
            config_manager = ConfigManager(str(readonly_dir))
            config = config_manager.load_config()
            
            # Attempt to save configuration should handle permission error
            with pytest.raises(Exception):  # Should raise some form of permission error
                config_manager.save_config(config, str(readonly_dir / "config.yaml"))
        
        finally:
            # Restore permissions for cleanup
            readonly_dir.chmod(0o755)