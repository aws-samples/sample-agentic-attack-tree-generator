"""
Unit tests for ThreatForest configuration management.
"""

import os
import tempfile
import yaml
from pathlib import Path
from unittest.mock import patch, Mock

import pytest

from threatforest.config import (
    ConfigManager,
    ThreatForestConfig,
    BedrockConfig,
    ProcessingConfig,
    OutputConfig,
    FileConfig,
    TTCConfig,
    ValidationResult,
    ValidationError,
)


class TestBedrockConfig:
    """Test cases for BedrockConfig model."""
    
    def test_bedrock_config_defaults(self):
        """Test default values for BedrockConfig."""
        config = BedrockConfig()
        
        assert config.region == "us-east-1"
        assert config.model == "anthropic.claude-3-sonnet-20240229-v1:0"
        assert config.api_key_source == "environment"
        assert config.timeout_seconds == 300
        
        # Test new enhanced configuration defaults
        assert config.temperature == 0.1
        assert config.max_tokens == 4000
        assert config.top_p == 0.9
        assert config.custom_parameters == {}
        assert config.validation_status == "unknown"
        assert config.last_validated is None
    
    def test_bedrock_config_custom_values(self):
        """Test custom values for BedrockConfig."""
        from datetime import datetime
        
        test_datetime = datetime.now()
        config = BedrockConfig(
            region="us-west-2",
            model="anthropic.claude-3-haiku-20240307-v1:0",
            api_key_source="file",
            timeout_seconds=600,
            temperature=0.7,
            max_tokens=8000,
            top_p=0.95,
            custom_parameters={"stop_sequences": ["Human:", "Assistant:"]},
            validation_status="valid",
            last_validated=test_datetime
        )
        
        assert config.region == "us-west-2"
        assert config.model == "anthropic.claude-3-haiku-20240307-v1:0"
        assert config.api_key_source == "file"
        assert config.timeout_seconds == 600
        
        # Test new enhanced configuration values
        assert config.temperature == 0.7
        assert config.max_tokens == 8000
        assert config.top_p == 0.95
        assert config.custom_parameters == {"stop_sequences": ["Human:", "Assistant:"]}
        assert config.validation_status == "valid"
        assert config.last_validated == test_datetime
    
    def test_bedrock_config_temperature_validation(self):
        """Test temperature parameter validation."""
        # Valid values
        config = BedrockConfig(temperature=0.0)
        assert config.temperature == 0.0
        
        config = BedrockConfig(temperature=1.0)
        assert config.temperature == 1.0
        
        config = BedrockConfig(temperature=0.5)
        assert config.temperature == 0.5
        
        # Invalid values should raise ValidationError
        with pytest.raises(Exception):  # Pydantic ValidationError
            BedrockConfig(temperature=-0.1)
        
        with pytest.raises(Exception):  # Pydantic ValidationError
            BedrockConfig(temperature=1.1)
    
    def test_bedrock_config_max_tokens_validation(self):
        """Test max_tokens parameter validation."""
        # Valid values
        config = BedrockConfig(max_tokens=1)
        assert config.max_tokens == 1
        
        config = BedrockConfig(max_tokens=100000)
        assert config.max_tokens == 100000
        
        config = BedrockConfig(max_tokens=5000)
        assert config.max_tokens == 5000
        
        # Invalid values should raise ValidationError
        with pytest.raises(Exception):  # Pydantic ValidationError
            BedrockConfig(max_tokens=0)
        
        with pytest.raises(Exception):  # Pydantic ValidationError
            BedrockConfig(max_tokens=100001)
    
    def test_bedrock_config_top_p_validation(self):
        """Test top_p parameter validation."""
        # Valid values
        config = BedrockConfig(top_p=0.0)
        assert config.top_p == 0.0
        
        config = BedrockConfig(top_p=1.0)
        assert config.top_p == 1.0
        
        config = BedrockConfig(top_p=0.9)
        assert config.top_p == 0.9
        
        # Invalid values should raise ValidationError
        with pytest.raises(Exception):  # Pydantic ValidationError
            BedrockConfig(top_p=-0.1)
        
        with pytest.raises(Exception):  # Pydantic ValidationError
            BedrockConfig(top_p=1.1)
    
    def test_bedrock_config_custom_parameters_dict(self):
        """Test custom_parameters field accepts various dictionary values."""
        custom_params = {
            "stop_sequences": ["Human:", "Assistant:"],
            "repetition_penalty": 1.1,
            "seed": 42,
            "system_prompt": "You are a helpful assistant"
        }
        
        config = BedrockConfig(custom_parameters=custom_params)
        assert config.custom_parameters == custom_params
        
        # Test empty dict
        config = BedrockConfig(custom_parameters={})
        assert config.custom_parameters == {}
    
    def test_bedrock_config_validation_status_values(self):
        """Test validation_status field accepts string values."""
        for status in ["unknown", "valid", "invalid", "pending"]:
            config = BedrockConfig(validation_status=status)
            assert config.validation_status == status


class TestProcessingConfig:
    """Test cases for ProcessingConfig model."""
    
    def test_processing_config_defaults(self):
        """Test default values for ProcessingConfig."""
        config = ProcessingConfig()
        
        assert config.severity_threshold == "high"
        assert config.max_concurrent_agents == 4
        assert config.timeout_seconds == 300


class TestTTCConfig:
    """Test cases for TTCConfig model."""
    
    def test_ttc_config_defaults(self):
        """Test default values for TTCConfig."""
        config = TTCConfig()
        
        assert config.aaf_bundle_path == "./aaf-bundle.json"
        assert config.alignment_threshold == 0.8
        assert config.enable_enhancement is True
    
    def test_ttc_config_alignment_threshold_validation(self):
        """Test alignment threshold validation."""
        # Valid values
        config = TTCConfig(alignment_threshold=0.5)
        assert config.alignment_threshold == 0.5
        
        # Invalid values should raise ValidationError
        with pytest.raises(Exception):  # Pydantic ValidationError
            TTCConfig(alignment_threshold=1.5)
        
        with pytest.raises(Exception):  # Pydantic ValidationError
            TTCConfig(alignment_threshold=-0.1)


class TestThreatForestConfig:
    """Test cases for ThreatForestConfig model."""
    
    def test_threat_forest_config_defaults(self):
        """Test default configuration creation."""
        config = ThreatForestConfig()
        
        assert isinstance(config.bedrock, BedrockConfig)
        assert isinstance(config.processing, ProcessingConfig)
        assert isinstance(config.output, OutputConfig)
        assert isinstance(config.files, FileConfig)
        assert isinstance(config.ttc, TTCConfig)
    
    def test_threat_forest_config_nested_updates(self):
        """Test nested configuration updates."""
        config = ThreatForestConfig(
            bedrock=BedrockConfig(region="us-west-2"),
            processing=ProcessingConfig(severity_threshold="medium")
        )
        
        assert config.bedrock.region == "us-west-2"
        assert config.processing.severity_threshold == "medium"
        # Other values should remain default
        assert config.bedrock.model == "anthropic.claude-3-sonnet-20240229-v1:0"


class TestConfigManager:
    """Test cases for ConfigManager class."""
    
    def test_config_manager_initialization(self):
        """Test ConfigManager initialization."""
        manager = ConfigManager()
        assert manager.project_dir == Path.cwd()
        
        custom_dir = "/tmp/test"
        manager = ConfigManager(custom_dir)
        assert manager.project_dir == Path(custom_dir)
    
    def test_load_default_config(self):
        """Test loading default configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ConfigManager(temp_dir)
            config = manager.load_config()
            
            assert isinstance(config, ThreatForestConfig)
            assert config.bedrock.region == "us-east-1"
            assert config.processing.severity_threshold == "high"
    
    def test_get_config_before_load_raises_error(self):
        """Test that get_config raises error before load_config."""
        manager = ConfigManager()
        
        with pytest.raises(RuntimeError, match="Configuration not loaded"):
            manager.get_config()
    
    def test_get_config_after_load(self):
        """Test get_config after load_config."""
        manager = ConfigManager()
        loaded_config = manager.load_config()
        retrieved_config = manager.get_config()
        
        assert loaded_config is retrieved_config
    
    def test_load_yaml_file_nonexistent(self):
        """Test loading non-existent YAML file."""
        manager = ConfigManager()
        result = manager._load_yaml_file(Path("/nonexistent/file.yaml"))
        
        assert result is None
    
    def test_load_yaml_file_valid(self):
        """Test loading valid YAML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                'bedrock': {'region': 'us-west-2'},
                'processing': {'severity_threshold': 'medium'}
            }, f)
            temp_path = f.name
        
        try:
            manager = ConfigManager()
            result = manager._load_yaml_file(Path(temp_path))
            
            assert result is not None
            assert result['bedrock']['region'] == 'us-west-2'
            assert result['processing']['severity_threshold'] == 'medium'
        finally:
            os.unlink(temp_path)
    
    def test_load_yaml_file_invalid(self):
        """Test loading invalid YAML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: content: [")
            temp_path = f.name
        
        try:
            manager = ConfigManager()
            
            with pytest.raises(ValueError, match="Error loading config file"):
                manager._load_yaml_file(Path(temp_path))
        finally:
            os.unlink(temp_path)
    
    def test_convert_env_value(self):
        """Test environment variable value conversion."""
        manager = ConfigManager()
        
        # Boolean values
        assert manager._convert_env_value("true") is True
        assert manager._convert_env_value("True") is True
        assert manager._convert_env_value("yes") is True
        assert manager._convert_env_value("1") is True
        assert manager._convert_env_value("false") is False
        assert manager._convert_env_value("False") is False
        assert manager._convert_env_value("no") is False
        assert manager._convert_env_value("0") is False
        
        # Numeric values
        assert manager._convert_env_value("42") == 42
        assert manager._convert_env_value("3.14") == 3.14
        
        # String values
        assert manager._convert_env_value("hello") == "hello"
        assert manager._convert_env_value("us-east-1") == "us-east-1"
    
    def test_load_env_config(self):
        """Test loading configuration from environment variables."""
        env_vars = {
            'TF_BEDROCK_REGION': 'us-west-2',
            'TF_BEDROCK_TIMEOUT_SECONDS': '600',
            'TF_PROCESSING_SEVERITY_THRESHOLD': 'medium',
            'TF_TTC_ENABLE_ENHANCEMENT': 'false',
            'OTHER_VAR': 'ignored'  # Should be ignored
        }
        
        with patch.dict(os.environ, env_vars, clear=False):
            manager = ConfigManager()
            env_config = manager._load_env_config()
        
        assert env_config['bedrock']['region'] == 'us-west-2'
        assert env_config['bedrock']['timeout_seconds'] == 600
        assert env_config['processing']['severity_threshold'] == 'medium'
        assert env_config['ttc']['enable_enhancement'] is False
        assert 'other_var' not in env_config
    
    def test_load_config_with_cli_args(self):
        """Test loading configuration with CLI arguments."""
        cli_args = {
            'bedrock': {'region': 'eu-west-1'},
            'output': {'directory': './custom-output'}
        }
        
        manager = ConfigManager()
        config = manager.load_config(cli_args=cli_args)
        
        assert config.bedrock.region == 'eu-west-1'
        assert config.output.directory == './custom-output'
        # Other values should remain default
        assert config.processing.severity_threshold == 'high'
    
    def test_update_config(self):
        """Test updating configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ConfigManager(temp_dir)
            config = manager.load_config()
            
            # Initial values
            assert config.bedrock.region == 'us-east-1'
            assert config.processing.severity_threshold == 'high'
            
            # Update configuration
            updates = {
                'bedrock': {'region': 'ap-southeast-1'},
                'processing': {'severity_threshold': 'low'}
            }
            
            updated_config = manager.update_config(updates)
            
            assert updated_config.bedrock.region == 'ap-southeast-1'
            assert updated_config.processing.severity_threshold == 'low'
            # Other values should remain unchanged
            assert updated_config.bedrock.model == "anthropic.claude-3-sonnet-20240229-v1:0"
    
    def test_update_config_before_load_raises_error(self):
        """Test that update_config raises error before load_config."""
        manager = ConfigManager()
        
        with pytest.raises(RuntimeError, match="Configuration not loaded"):
            manager.update_config({'bedrock': {'region': 'us-west-2'}})
    
    def test_deep_update(self):
        """Test deep dictionary update functionality."""
        manager = ConfigManager()
        
        base_dict = {
            'level1': {
                'level2': {
                    'key1': 'value1',
                    'key2': 'value2'
                },
                'other_key': 'other_value'
            }
        }
        
        update_dict = {
            'level1': {
                'level2': {
                    'key1': 'new_value1',
                    'key3': 'value3'
                }
            }
        }
        
        manager._deep_update(base_dict, update_dict)
        
        assert base_dict['level1']['level2']['key1'] == 'new_value1'
        assert base_dict['level1']['level2']['key2'] == 'value2'  # Unchanged
        assert base_dict['level1']['level2']['key3'] == 'value3'  # New
        assert base_dict['level1']['other_key'] == 'other_value'  # Unchanged
    
    def test_save_config(self):
        """Test saving configuration to file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "test_config.yaml"
            
            manager = ConfigManager()
            config = manager.load_config()
            
            # Modify some values including new enhanced parameters
            config.bedrock.region = "eu-central-1"
            config.bedrock.temperature = 0.8
            config.bedrock.max_tokens = 6000
            config.bedrock.top_p = 0.85
            config.bedrock.custom_parameters = {"stop_sequences": ["END"]}
            config.bedrock.validation_status = "valid"
            config.processing.severity_threshold = "medium"
            
            # Save configuration
            manager.save_config(config, str(config_path))
            
            # Verify file was created and contains correct data
            assert config_path.exists()
            
            with open(config_path, 'r') as f:
                saved_data = yaml.safe_load(f)
            
            assert saved_data['bedrock']['region'] == 'eu-central-1'
            assert saved_data['bedrock']['temperature'] == 0.8
            assert saved_data['bedrock']['max_tokens'] == 6000
            assert saved_data['bedrock']['top_p'] == 0.85
            assert saved_data['bedrock']['custom_parameters'] == {"stop_sequences": ["END"]}
            assert saved_data['bedrock']['validation_status'] == 'valid'
            assert saved_data['processing']['severity_threshold'] == 'medium'
    
    def test_load_config_with_enhanced_bedrock_parameters(self):
        """Test loading configuration with enhanced Bedrock parameters from file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                'bedrock': {
                    'region': 'us-west-2',
                    'model': 'anthropic.claude-3-haiku-20240307-v1:0',
                    'temperature': 0.6,
                    'max_tokens': 7000,
                    'top_p': 0.92,
                    'custom_parameters': {
                        'stop_sequences': ['Human:', 'Assistant:'],
                        'repetition_penalty': 1.05
                    },
                    'validation_status': 'valid'
                }
            }, f)
            temp_path = f.name
        
        try:
            manager = ConfigManager()
            config = manager.load_config(config_file=temp_path)
            
            assert config.bedrock.region == 'us-west-2'
            assert config.bedrock.model == 'anthropic.claude-3-haiku-20240307-v1:0'
            assert config.bedrock.temperature == 0.6
            assert config.bedrock.max_tokens == 7000
            assert config.bedrock.top_p == 0.92
            assert config.bedrock.custom_parameters == {
                'stop_sequences': ['Human:', 'Assistant:'],
                'repetition_penalty': 1.05
            }
            assert config.bedrock.validation_status == 'valid'
        finally:
            os.unlink(temp_path)
    
    def test_load_config_with_enhanced_env_vars(self):
        """Test loading enhanced Bedrock configuration from environment variables."""
        env_vars = {
            'TF_BEDROCK_REGION': 'eu-west-1',
            'TF_BEDROCK_TEMPERATURE': '0.75',
            'TF_BEDROCK_MAX_TOKENS': '8500',
            'TF_BEDROCK_TOP_P': '0.88',
            'TF_BEDROCK_VALIDATION_STATUS': 'pending'
        }
        
        with patch.dict(os.environ, env_vars, clear=False):
            manager = ConfigManager()
            config = manager.load_config()
        
        assert config.bedrock.region == 'eu-west-1'
        assert config.bedrock.temperature == 0.75
        assert config.bedrock.max_tokens == 8500
        assert config.bedrock.top_p == 0.88
        assert config.bedrock.validation_status == 'pending'
    
    def test_config_manager_logging_initialization(self):
        """Test that ConfigManager initializes logger correctly."""
        manager = ConfigManager()
        assert hasattr(manager, 'logger')
        assert manager.logger.name == 'threatforest.config'


class TestConfigurationValidation:
    """Test cases for configuration validation functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        self.manager = ConfigManager()
    
    def test_validate_configuration_no_config_loaded(self):
        """Test validation when no configuration is loaded."""
        result = self.manager.validate_configuration()
        
        assert result.is_valid is False
        assert len(result.errors) == 1
        assert result.errors[0].component == "config_manager"
        assert result.errors[0].error_type == "no_config"
        assert "No configuration loaded" in result.errors[0].message
        assert result.tested_components["config_manager"] is False
    
    def test_validate_configuration_success(self):
        """Test successful configuration validation by mocking validation methods."""
        # Mock the individual validation methods
        with patch.object(self.manager, '_validate_aws_credentials') as mock_aws_val, \
             patch.object(self.manager, '_validate_bedrock_configuration') as mock_bedrock_val, \
             patch.object(self.manager, '_test_bedrock_connectivity') as mock_connectivity_val, \
             patch.object(self.manager, '_validate_other_config_sections') as mock_other_val:
            
            # Mock successful AWS credentials validation
            mock_aws_val.return_value = {
                "is_valid": True,
                "account_id": "123456789012",
                "user_arn": "arn:aws:iam::123456789012:user/test",
                "user_id": "AIDACKCEVSQ6C2EXAMPLE"
            }
            
            # Mock successful Bedrock configuration validation
            mock_bedrock_val.return_value = {
                "is_valid": True,
                "errors": [],
                "warnings": []
            }
            
            # Mock successful Bedrock connectivity test
            mock_connectivity_val.return_value = {
                "is_valid": True
            }
            
            # Mock successful other config validation
            mock_other_val.return_value = {
                "warnings": [],
                "tested_components": {
                    "processing_config": True,
                    "output_config": True,
                    "ttc_config": True
                }
            }
            
            # Load configuration and validate
            config = self.manager.load_config()
            result = self.manager.validate_configuration(config)
            
            assert result.is_valid is True
            assert len(result.errors) == 0
            assert result.tested_components["aws_credentials"] is True
            assert result.tested_components["bedrock_config"] is True
            assert result.tested_components["bedrock_connectivity"] is True
    
    @patch('threatforest.config.boto3.Session')
    def test_validate_configuration_no_aws_credentials(self, mock_session):
        """Test validation with no AWS credentials."""
        from botocore.exceptions import NoCredentialsError
        
        mock_session_instance = Mock()
        mock_session_instance.get_credentials.return_value = None
        mock_session.return_value = mock_session_instance
        
        config = self.manager.load_config()
        result = self.manager.validate_configuration(config)
        
        assert result.is_valid is False
        assert any(error.component == "aws_credentials" for error in result.errors)
        assert any(error.error_type == "no_credentials" for error in result.errors)
        assert result.tested_components["aws_credentials"] is False
    
    @patch('threatforest.config.boto3.Session')
    def test_validate_configuration_invalid_aws_credentials(self, mock_session):
        """Test validation with invalid AWS credentials."""
        from botocore.exceptions import ClientError
        
        mock_sts_client = Mock()
        mock_sts_client.get_caller_identity.side_effect = ClientError(
            error_response={
                'Error': {
                    'Code': 'InvalidUserID.NotFound',
                    'Message': 'Invalid credentials'
                }
            },
            operation_name='GetCallerIdentity'
        )
        mock_session_instance = Mock()
        mock_session_instance.get_credentials.return_value = Mock(
            access_key='invalid_key',
            secret_key='invalid_secret'
        )
        mock_session_instance.client.return_value = mock_sts_client
        mock_session.return_value = mock_session_instance
        
        config = self.manager.load_config()
        result = self.manager.validate_configuration(config)
        
        assert result.is_valid is False
        assert any(error.component == "aws_credentials" for error in result.errors)
        assert any(error.error_type == "invalid_credentials" for error in result.errors)
        assert result.tested_components["aws_credentials"] is False
    
    def test_validate_bedrock_configuration_invalid_model(self):
        """Test Bedrock configuration validation with invalid model."""
        config = ThreatForestConfig(
            bedrock=BedrockConfig(model="")
        )
        
        result = self.manager._validate_bedrock_configuration(config.bedrock)
        
        assert result["is_valid"] is False
        assert any(error["error_type"] == "invalid_model" for error in result["errors"])
    
    def test_validate_bedrock_configuration_invalid_temperature(self):
        """Test Bedrock configuration validation with invalid temperature."""
        # Create a valid config first, then modify the temperature directly
        config = BedrockConfig()
        # Bypass Pydantic validation by setting the attribute directly
        config.__dict__['temperature'] = 1.5
        
        result = self.manager._validate_bedrock_configuration(config)
        
        assert result["is_valid"] is False
        assert any(error["error_type"] == "invalid_temperature" for error in result["errors"])
    
    def test_validate_bedrock_configuration_invalid_max_tokens(self):
        """Test Bedrock configuration validation with invalid max_tokens."""
        # Create a valid config first, then modify the max_tokens directly
        config = BedrockConfig()
        # Bypass Pydantic validation by setting the attribute directly
        config.__dict__['max_tokens'] = -100
        
        result = self.manager._validate_bedrock_configuration(config)
        
        assert result["is_valid"] is False
        assert any(error["error_type"] == "invalid_max_tokens" for error in result["errors"])
    
    def test_validate_bedrock_configuration_invalid_top_p(self):
        """Test Bedrock configuration validation with invalid top_p."""
        # Create a valid config first, then modify the top_p directly
        config = BedrockConfig()
        # Bypass Pydantic validation by setting the attribute directly
        config.__dict__['top_p'] = 2.0
        
        result = self.manager._validate_bedrock_configuration(config)
        
        assert result["is_valid"] is False
        assert any(error["error_type"] == "invalid_top_p" for error in result["errors"])
    
    def test_validate_bedrock_configuration_warnings(self):
        """Test Bedrock configuration validation with warnings."""
        config = ThreatForestConfig(
            bedrock=BedrockConfig(
                region="ap-south-1",  # Less common region
                timeout_seconds=15,   # Low timeout
                max_tokens=99000      # High max tokens (above 100000 threshold)
            )
        )
        
        result = self.manager._validate_bedrock_configuration(config.bedrock)
        
        assert result["is_valid"] is True  # No errors, just warnings
        assert len(result["warnings"]) >= 1  # Should have at least region or timeout warnings
        assert any(warning["error_type"] == "low_timeout" for warning in result["warnings"])
    
    def test_validate_configuration_bedrock_connectivity_failure(self):
        """Test validation when Bedrock connectivity fails."""
        # Mock the individual validation methods
        with patch.object(self.manager, '_validate_aws_credentials') as mock_aws_val, \
             patch.object(self.manager, '_validate_bedrock_configuration') as mock_bedrock_val, \
             patch.object(self.manager, '_test_bedrock_connectivity') as mock_connectivity_val, \
             patch.object(self.manager, '_validate_other_config_sections') as mock_other_val:
            
            # Mock successful AWS credentials validation
            mock_aws_val.return_value = {
                "is_valid": True,
                "account_id": "123456789012",
                "user_arn": "arn:aws:iam::123456789012:user/test",
                "user_id": "AIDACKCEVSQ6C2EXAMPLE"
            }
            
            # Mock successful Bedrock configuration validation
            mock_bedrock_val.return_value = {
                "is_valid": True,
                "errors": [],
                "warnings": []
            }
            
            # Mock failed Bedrock connectivity test
            mock_connectivity_val.return_value = {
                "is_valid": False,
                "error_type": "connectivity_failed",
                "message": "Failed to connect to Bedrock service",
                "suggestion": "Check network connectivity and AWS credentials"
            }
            
            # Mock successful other config validation
            mock_other_val.return_value = {
                "warnings": [],
                "tested_components": {
                    "processing_config": True,
                    "output_config": True,
                    "ttc_config": True
                }
            }
            
            config = self.manager.load_config()
            result = self.manager.validate_configuration(config)
            
            assert result.is_valid is False
            assert any(error.component == "bedrock_connectivity" for error in result.errors)
            assert any(error.error_type == "connectivity_failed" for error in result.errors)
            assert result.tested_components["bedrock_connectivity"] is False
    
    def test_validate_configuration_bedrock_client_error(self):
        """Test validation when BedrockClient raises an error."""
        # Mock the individual validation methods
        with patch.object(self.manager, '_validate_aws_credentials') as mock_aws_val, \
             patch.object(self.manager, '_validate_bedrock_configuration') as mock_bedrock_val, \
             patch.object(self.manager, '_test_bedrock_connectivity') as mock_connectivity_val, \
             patch.object(self.manager, '_validate_other_config_sections') as mock_other_val:
            
            # Mock successful AWS credentials validation
            mock_aws_val.return_value = {
                "is_valid": True,
                "account_id": "123456789012",
                "user_arn": "arn:aws:iam::123456789012:user/test",
                "user_id": "AIDACKCEVSQ6C2EXAMPLE"
            }
            
            # Mock successful Bedrock configuration validation
            mock_bedrock_val.return_value = {
                "is_valid": True,
                "errors": [],
                "warnings": []
            }
            
            # Mock Bedrock client error
            mock_connectivity_val.return_value = {
                "is_valid": False,
                "error_type": "bedrock_client_error",
                "message": "Bedrock client error: Access denied",
                "suggestion": "Check your AWS permissions for Bedrock service"
            }
            
            # Mock successful other config validation
            mock_other_val.return_value = {
                "warnings": [],
                "tested_components": {
                    "processing_config": True,
                    "output_config": True,
                    "ttc_config": True
                }
            }
            
            config = self.manager.load_config()
            result = self.manager.validate_configuration(config)
            
            assert result.is_valid is False
            assert any(error.component == "bedrock_connectivity" for error in result.errors)
            assert any(error.error_type == "bedrock_client_error" for error in result.errors)
            # Check that the error message contains relevant information
            error_messages = [error.message for error in result.errors]
            assert any("Access denied" in msg for msg in error_messages)
    
    def test_validate_other_config_sections_warnings(self):
        """Test validation of other configuration sections with warnings."""
        config = ThreatForestConfig(
            processing=ProcessingConfig(
                severity_threshold="invalid",
                max_concurrent_agents=-1
            ),
            ttc=TTCConfig(
                aaf_bundle_path="/nonexistent/path/bundle.json"
            )
        )
        
        result = self.manager._validate_other_config_sections(config)
        
        assert len(result["warnings"]) >= 2
        assert any(warning["error_type"] == "invalid_severity" for warning in result["warnings"])
        assert any(warning["error_type"] == "invalid_concurrency" for warning in result["warnings"])
        assert result["tested_components"]["processing_config"] is True
    
    def test_validation_result_dataclass(self):
        """Test ValidationResult dataclass creation."""
        from threatforest.config import ValidationResult, ValidationError
        from datetime import datetime
        
        errors = [ValidationError(
            component="test",
            error_type="test_error",
            message="Test error message",
            suggestion="Test suggestion"
        )]
        
        result = ValidationResult(
            is_valid=False,
            errors=errors,
            warnings=[],
            tested_components={"test": False},
            validation_time=datetime.now()
        )
        
        assert result.is_valid is False
        assert len(result.errors) == 1
        assert result.errors[0].component == "test"
        assert result.errors[0].error_type == "test_error"
        assert result.errors[0].message == "Test error message"
        assert result.errors[0].suggestion == "Test suggestion"
    
    def test_validation_error_dataclass(self):
        """Test ValidationError dataclass creation."""
        from threatforest.config import ValidationError
        
        error = ValidationError(
            component="bedrock",
            error_type="invalid_model",
            message="Model ID is invalid",
            suggestion="Use a valid model ID"
        )
        
        assert error.component == "bedrock"
        assert error.error_type == "invalid_model"
        assert error.message == "Model ID is invalid"
        assert error.suggestion == "Use a valid model ID"
        
        # Test without suggestion
        error_no_suggestion = ValidationError(
            component="aws",
            error_type="no_credentials",
            message="No credentials found"
        )
        
        assert error_no_suggestion.suggestion is None
    
    def test_validate_configuration_updates_bedrock_status(self):
        """Test that validation updates the Bedrock configuration status."""
        # Mock the individual validation methods for successful validation
        with patch.object(self.manager, '_validate_aws_credentials') as mock_aws_val, \
             patch.object(self.manager, '_validate_bedrock_configuration') as mock_bedrock_val, \
             patch.object(self.manager, '_test_bedrock_connectivity') as mock_connectivity_val, \
             patch.object(self.manager, '_validate_other_config_sections') as mock_other_val:
            
            # Mock successful AWS credentials validation
            mock_aws_val.return_value = {
                "is_valid": True,
                "account_id": "123456789012",
                "user_arn": "arn:aws:iam::123456789012:user/test",
                "user_id": "AIDACKCEVSQ6C2EXAMPLE"
            }
            
            # Mock successful Bedrock configuration validation
            mock_bedrock_val.return_value = {
                "is_valid": True,
                "errors": [],
                "warnings": []
            }
            
            # Mock successful Bedrock connectivity test
            mock_connectivity_val.return_value = {
                "is_valid": True
            }
            
            # Mock successful other config validation
            mock_other_val.return_value = {
                "warnings": [],
                "tested_components": {
                    "processing_config": True,
                    "output_config": True,
                    "ttc_config": True
                }
            }
            
            config = self.manager.load_config()
            original_status = config.bedrock.validation_status
            original_validated = config.bedrock.last_validated
            
            result = self.manager.validate_configuration(config)
            
            assert result.is_valid is True
            assert config.bedrock.validation_status == "valid"
            assert config.bedrock.last_validated is not None
            assert config.bedrock.last_validated != original_validated
    
    def test_validate_configuration_with_provided_config(self):
        """Test validation with explicitly provided configuration."""
        config = ThreatForestConfig(
            bedrock=BedrockConfig(model="")  # Invalid model
        )
        
        result = self.manager.validate_configuration(config)
        
        assert result.is_valid is False
        assert any(error.component == "bedrock_config" for error in result.errors)
        # Should not affect the manager's internal config
        assert self.manager._config is None