#!/usr/bin/env python3
"""
Unit tests for LangfuseConfig module

Tests configuration loading from environment variables and config files,
as well as validation of credentials when Langfuse is enabled.

Requirements tested:
- 1.1: Support Langfuse settings including public_key, secret_key, host, and enabled flag
- 1.3: Raise descriptive error when enabled but credentials missing
- 1.4: Support loading from environment variables with LANGFUSE_ prefix
- 1.5: Support loading from config.yaml file
"""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from threatforest.tracing.config import LangfuseConfig


class TestLangfuseConfigDefaults:
    """Test default values for LangfuseConfig"""
    
    def test_default_values(self):
        """Test that default values are set correctly"""
        config = LangfuseConfig()
        
        assert config.enabled is False
        assert config.public_key is None
        assert config.secret_key is None
        assert config.host == "https://cloud.langfuse.com"
    
    def test_custom_values(self):
        """Test that custom values can be set"""
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test-123",
            secret_key="sk-test-456",
            host="https://custom.langfuse.com"
        )
        
        assert config.enabled is True
        assert config.public_key == "pk-test-123"
        assert config.secret_key == "sk-test-456"
        assert config.host == "https://custom.langfuse.com"


class TestLangfuseConfigFromEnv:
    """Test loading configuration from environment variables"""
    
    def test_from_env_disabled_by_default(self):
        """Test that Langfuse is disabled when LANGFUSE_ENABLED is not set"""
        with patch.dict(os.environ, {}, clear=True):
            config = LangfuseConfig.from_env()
            
            assert config.enabled is False
            assert config.public_key is None
            assert config.secret_key is None
            assert config.host == "https://cloud.langfuse.com"
    
    def test_from_env_enabled_true(self):
        """Test loading enabled=true from environment"""
        env_vars = {
            "LANGFUSE_ENABLED": "true",
            "LANGFUSE_PUBLIC_KEY": "pk-env-123",
            "LANGFUSE_SECRET_KEY": "sk-env-456",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            config = LangfuseConfig.from_env()
            
            assert config.enabled is True
            assert config.public_key == "pk-env-123"
            assert config.secret_key == "sk-env-456"
    
    def test_from_env_enabled_case_insensitive(self):
        """Test that LANGFUSE_ENABLED is case-insensitive"""
        for value in ["TRUE", "True", "true", "TrUe"]:
            with patch.dict(os.environ, {"LANGFUSE_ENABLED": value}, clear=True):
                config = LangfuseConfig.from_env()
                assert config.enabled is True, f"Failed for value: {value}"
    
    def test_from_env_enabled_false_values(self):
        """Test that non-'true' values result in enabled=False"""
        for value in ["false", "False", "FALSE", "0", "no", "", "anything"]:
            with patch.dict(os.environ, {"LANGFUSE_ENABLED": value}, clear=True):
                config = LangfuseConfig.from_env()
                assert config.enabled is False, f"Failed for value: {value}"
    
    def test_from_env_custom_host(self):
        """Test loading custom host from environment"""
        env_vars = {
            "LANGFUSE_HOST": "https://self-hosted.example.com",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            config = LangfuseConfig.from_env()
            
            assert config.host == "https://self-hosted.example.com"
    
    def test_from_env_default_host_when_not_set(self):
        """Test that default host is used when LANGFUSE_HOST is not set"""
        with patch.dict(os.environ, {}, clear=True):
            config = LangfuseConfig.from_env()
            
            assert config.host == "https://cloud.langfuse.com"


class TestLangfuseConfigFromConfigFile:
    """Test loading configuration from config.yaml"""
    
    def test_from_config_file_with_all_values(self):
        """Test loading all values from config file"""
        mock_config = MagicMock()
        mock_config.get.return_value = {
            "enabled": True,
            "public_key": "pk-config-123",
            "secret_key": "sk-config-456",
            "host": "https://config.langfuse.com"
        }
        
        config = LangfuseConfig.from_config_file(mock_config)
        
        assert config.enabled is True
        assert config.public_key == "pk-config-123"
        assert config.secret_key == "sk-config-456"
        assert config.host == "https://config.langfuse.com"
        mock_config.get.assert_called_once_with("langfuse", {})
    
    def test_from_config_file_with_missing_section(self):
        """Test that defaults are used when langfuse section is missing"""
        mock_config = MagicMock()
        mock_config.get.return_value = {}
        
        config = LangfuseConfig.from_config_file(mock_config)
        
        assert config.enabled is False
        assert config.public_key is None
        assert config.secret_key is None
        assert config.host == "https://cloud.langfuse.com"
    
    def test_from_config_file_with_none_section(self):
        """Test that defaults are used when langfuse section is None"""
        mock_config = MagicMock()
        mock_config.get.return_value = None
        
        config = LangfuseConfig.from_config_file(mock_config)
        
        assert config.enabled is False
        assert config.public_key is None
        assert config.secret_key is None
        assert config.host == "https://cloud.langfuse.com"
    
    def test_from_config_file_with_partial_values(self):
        """Test loading partial values from config file"""
        mock_config = MagicMock()
        mock_config.get.return_value = {
            "enabled": True,
            "public_key": "pk-partial-123",
            # secret_key and host not provided
        }
        
        config = LangfuseConfig.from_config_file(mock_config)
        
        assert config.enabled is True
        assert config.public_key == "pk-partial-123"
        assert config.secret_key is None
        assert config.host == "https://cloud.langfuse.com"


class TestLangfuseConfigValidation:
    """Test configuration validation"""
    
    def test_validate_disabled_no_credentials(self):
        """Test that validation passes when disabled without credentials"""
        config = LangfuseConfig(enabled=False)
        
        # Should not raise
        config.validate()
    
    def test_validate_disabled_with_credentials(self):
        """Test that validation passes when disabled with credentials"""
        config = LangfuseConfig(
            enabled=False,
            public_key="pk-test",
            secret_key="sk-test"
        )
        
        # Should not raise
        config.validate()
    
    def test_validate_enabled_with_credentials(self):
        """Test that validation passes when enabled with credentials"""
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test"
        )
        
        # Should not raise
        config.validate()
    
    def test_validate_enabled_missing_public_key(self):
        """Test that validation fails when enabled but public_key is missing"""
        config = LangfuseConfig(
            enabled=True,
            public_key=None,
            secret_key="sk-test"
        )
        
        with pytest.raises(ValueError) as exc_info:
            config.validate()
        
        assert "Langfuse is enabled but credentials are missing" in str(exc_info.value)
        assert "LANGFUSE_PUBLIC_KEY" in str(exc_info.value)
        assert "LANGFUSE_SECRET_KEY" in str(exc_info.value)
    
    def test_validate_enabled_missing_secret_key(self):
        """Test that validation fails when enabled but secret_key is missing"""
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key=None
        )
        
        with pytest.raises(ValueError) as exc_info:
            config.validate()
        
        assert "Langfuse is enabled but credentials are missing" in str(exc_info.value)
    
    def test_validate_enabled_missing_both_keys(self):
        """Test that validation fails when enabled but both keys are missing"""
        config = LangfuseConfig(
            enabled=True,
            public_key=None,
            secret_key=None
        )
        
        with pytest.raises(ValueError) as exc_info:
            config.validate()
        
        assert "Langfuse is enabled but credentials are missing" in str(exc_info.value)
    
    def test_validate_enabled_empty_public_key(self):
        """Test that validation fails when enabled but public_key is empty string"""
        config = LangfuseConfig(
            enabled=True,
            public_key="",
            secret_key="sk-test"
        )
        
        with pytest.raises(ValueError) as exc_info:
            config.validate()
        
        assert "Langfuse is enabled but credentials are missing" in str(exc_info.value)
    
    def test_validate_enabled_empty_secret_key(self):
        """Test that validation fails when enabled but secret_key is empty string"""
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key=""
        )
        
        with pytest.raises(ValueError) as exc_info:
            config.validate()
        
        assert "Langfuse is enabled but credentials are missing" in str(exc_info.value)


class TestLangfuseConfigDataclass:
    """Test dataclass behavior"""
    
    def test_equality(self):
        """Test that two configs with same values are equal"""
        config1 = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",
            host="https://test.com"
        )
        config2 = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",
            host="https://test.com"
        )
        
        assert config1 == config2
    
    def test_inequality(self):
        """Test that two configs with different values are not equal"""
        config1 = LangfuseConfig(enabled=True)
        config2 = LangfuseConfig(enabled=False)
        
        assert config1 != config2
    
    def test_repr(self):
        """Test that repr includes all fields"""
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",
            host="https://test.com"
        )
        
        repr_str = repr(config)
        assert "enabled=True" in repr_str
        assert "public_key='pk-test'" in repr_str
        assert "secret_key='sk-test'" in repr_str
        assert "host='https://test.com'" in repr_str


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
