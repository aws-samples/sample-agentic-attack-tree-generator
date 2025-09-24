"""
Unit tests for ThreatForest configuration management.
"""

import os
import tempfile
import yaml
from pathlib import Path
from unittest.mock import patch

import pytest

from threatforest.config import (
    ConfigManager,
    ThreatForestConfig,
    BedrockConfig,
    ProcessingConfig,
    OutputConfig,
    FileConfig,
    TTCConfig,
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
    
    def test_bedrock_config_custom_values(self):
        """Test custom values for BedrockConfig."""
        config = BedrockConfig(
            region="us-west-2",
            model="anthropic.claude-3-haiku-20240307-v1:0",
            api_key_source="file",
            timeout_seconds=600
        )
        
        assert config.region == "us-west-2"
        assert config.model == "anthropic.claude-3-haiku-20240307-v1:0"
        assert config.api_key_source == "file"
        assert config.timeout_seconds == 600


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
        manager = ConfigManager()
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
        manager = ConfigManager()
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
            
            # Modify some values
            config.bedrock.region = "eu-central-1"
            config.processing.severity_threshold = "medium"
            
            # Save configuration
            manager.save_config(config, str(config_path))
            
            # Verify file was created and contains correct data
            assert config_path.exists()
            
            with open(config_path, 'r') as f:
                saved_data = yaml.safe_load(f)
            
            assert saved_data['bedrock']['region'] == 'eu-central-1'
            assert saved_data['processing']['severity_threshold'] == 'medium'