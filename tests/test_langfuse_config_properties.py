#!/usr/bin/env python3
"""
Property-Based Tests for LangfuseConfig Module

This module contains property-based tests using Hypothesis to validate
the correctness properties of the LangfuseConfig class.

Properties tested:
- Property 1: Configuration Loading Round-Trip
- Property 2: Invalid Configuration Raises Error

Validates: Requirements 1.1, 1.3, 1.4, 1.5
"""

import os
import sys
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings, strategies as st, assume

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from threatforest.tracing.config import LangfuseConfig


# =============================================================================
# Hypothesis Strategies for generating test data
# =============================================================================

# Strategy for generating valid non-empty strings (for keys)
non_empty_string = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S")),
    min_size=1,
    max_size=100
).filter(lambda s: s.strip() != "")

# Strategy for generating valid API keys (non-empty strings)
api_key_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=10,
    max_size=50
).filter(lambda s: len(s.strip()) > 0)

# Strategy for generating valid host URLs
host_strategy = st.sampled_from([
    "https://cloud.langfuse.com",
    "https://us.cloud.langfuse.com",
    "https://eu.cloud.langfuse.com",
    "https://self-hosted.example.com",
    "https://langfuse.internal.company.com",
])

# Strategy for generating valid complete configurations
valid_config_strategy = st.builds(
    LangfuseConfig,
    enabled=st.booleans(),
    public_key=st.one_of(st.none(), api_key_strategy),
    secret_key=st.one_of(st.none(), api_key_strategy),
    host=host_strategy,
)

# Strategy for generating valid enabled configurations (with credentials)
valid_enabled_config_strategy = st.builds(
    LangfuseConfig,
    enabled=st.just(True),
    public_key=api_key_strategy,
    secret_key=api_key_strategy,
    host=host_strategy,
)

# Strategy for generating invalid configurations (enabled but missing credentials)
invalid_config_strategy = st.one_of(
    # Missing public_key
    st.builds(
        LangfuseConfig,
        enabled=st.just(True),
        public_key=st.none(),
        secret_key=api_key_strategy,
        host=host_strategy,
    ),
    # Missing secret_key
    st.builds(
        LangfuseConfig,
        enabled=st.just(True),
        public_key=api_key_strategy,
        secret_key=st.none(),
        host=host_strategy,
    ),
    # Missing both keys
    st.builds(
        LangfuseConfig,
        enabled=st.just(True),
        public_key=st.none(),
        secret_key=st.none(),
        host=host_strategy,
    ),
    # Empty public_key
    st.builds(
        LangfuseConfig,
        enabled=st.just(True),
        public_key=st.just(""),
        secret_key=api_key_strategy,
        host=host_strategy,
    ),
    # Empty secret_key
    st.builds(
        LangfuseConfig,
        enabled=st.just(True),
        public_key=api_key_strategy,
        secret_key=st.just(""),
        host=host_strategy,
    ),
)


# =============================================================================
# Property 1: Configuration Loading Round-Trip
# =============================================================================

class TestProperty1ConfigurationRoundTrip:
    """
    Feature: langfuse-evaluation-integration, Property 1: Configuration Loading Round-Trip
    
    *For any* valid Langfuse configuration (from environment variables or config.yaml),
    loading the configuration and accessing its fields SHALL return the original values.
    
    **Validates: Requirements 1.1, 1.4, 1.5**
    """
    
    @settings(max_examples=100)
    @given(
        enabled=st.booleans(),
        public_key=st.one_of(st.none(), api_key_strategy),
        secret_key=st.one_of(st.none(), api_key_strategy),
        host=host_strategy,
    )
    def test_env_round_trip_preserves_values(
        self,
        enabled: bool,
        public_key: Optional[str],
        secret_key: Optional[str],
        host: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 1: Configuration Loading Round-Trip
        
        Test that loading configuration from environment variables preserves all values.
        """
        # Build environment variables
        env_vars = {
            "LANGFUSE_ENABLED": "true" if enabled else "false",
            "LANGFUSE_HOST": host,
        }
        if public_key is not None:
            env_vars["LANGFUSE_PUBLIC_KEY"] = public_key
        if secret_key is not None:
            env_vars["LANGFUSE_SECRET_KEY"] = secret_key
        
        # Load config from environment
        with patch.dict(os.environ, env_vars, clear=True):
            config = LangfuseConfig.from_env()
        
        # Verify round-trip: all values should match original inputs
        assert config.enabled == enabled, f"enabled mismatch: {config.enabled} != {enabled}"
        assert config.public_key == public_key, f"public_key mismatch: {config.public_key} != {public_key}"
        assert config.secret_key == secret_key, f"secret_key mismatch: {config.secret_key} != {secret_key}"
        assert config.host == host, f"host mismatch: {config.host} != {host}"
    
    @settings(max_examples=100)
    @given(
        enabled=st.booleans(),
        public_key=st.one_of(st.none(), api_key_strategy),
        secret_key=st.one_of(st.none(), api_key_strategy),
        host=host_strategy,
    )
    def test_config_file_round_trip_preserves_values(
        self,
        enabled: bool,
        public_key: Optional[str],
        secret_key: Optional[str],
        host: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 1: Configuration Loading Round-Trip
        
        Test that loading configuration from config file preserves all values.
        """
        # Build mock config object
        mock_config = MagicMock()
        mock_config.get.return_value = {
            "enabled": enabled,
            "public_key": public_key,
            "secret_key": secret_key,
            "host": host,
        }
        
        # Load config from config file
        config = LangfuseConfig.from_config_file(mock_config)
        
        # Verify round-trip: all values should match original inputs
        assert config.enabled == enabled, f"enabled mismatch: {config.enabled} != {enabled}"
        assert config.public_key == public_key, f"public_key mismatch: {config.public_key} != {public_key}"
        assert config.secret_key == secret_key, f"secret_key mismatch: {config.secret_key} != {secret_key}"
        assert config.host == host, f"host mismatch: {config.host} != {host}"
    
    @settings(max_examples=100)
    @given(config=valid_config_strategy)
    def test_direct_construction_round_trip(self, config: LangfuseConfig):
        """
        Feature: langfuse-evaluation-integration, Property 1: Configuration Loading Round-Trip
        
        Test that directly constructed configurations preserve all field values.
        """
        # Access all fields and verify they match
        assert config.enabled == config.enabled
        assert config.public_key == config.public_key
        assert config.secret_key == config.secret_key
        assert config.host == config.host
        
        # Verify dataclass equality
        config_copy = LangfuseConfig(
            enabled=config.enabled,
            public_key=config.public_key,
            secret_key=config.secret_key,
            host=config.host,
        )
        assert config == config_copy
    
    @settings(max_examples=100)
    @given(host=host_strategy)
    def test_default_host_when_not_specified_in_env(self, host: str):
        """
        Feature: langfuse-evaluation-integration, Property 1: Configuration Loading Round-Trip
        
        Test that default host is used when LANGFUSE_HOST is not set in environment.
        """
        # Environment without LANGFUSE_HOST
        env_vars = {"LANGFUSE_ENABLED": "false"}
        
        with patch.dict(os.environ, env_vars, clear=True):
            config = LangfuseConfig.from_env()
        
        # Default host should be cloud.langfuse.com
        assert config.host == "https://cloud.langfuse.com"
    
    @settings(max_examples=100)
    @given(
        enabled=st.booleans(),
        public_key=st.one_of(st.none(), api_key_strategy),
        secret_key=st.one_of(st.none(), api_key_strategy),
    )
    def test_config_file_default_host_when_not_specified(
        self,
        enabled: bool,
        public_key: Optional[str],
        secret_key: Optional[str],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 1: Configuration Loading Round-Trip
        
        Test that default host is used when host is not specified in config file.
        """
        # Config without host key
        mock_config = MagicMock()
        mock_config.get.return_value = {
            "enabled": enabled,
            "public_key": public_key,
            "secret_key": secret_key,
            # host not specified
        }
        
        config = LangfuseConfig.from_config_file(mock_config)
        
        # Default host should be cloud.langfuse.com
        assert config.host == "https://cloud.langfuse.com"


# =============================================================================
# Property 2: Invalid Configuration Raises Error
# =============================================================================

class TestProperty2InvalidConfigurationRaisesError:
    """
    Feature: langfuse-evaluation-integration, Property 2: Invalid Configuration Raises Error
    
    *For any* configuration where `enabled=true` but `public_key` or `secret_key` is missing,
    calling `validate()` SHALL raise a `ValueError` with a descriptive message.
    
    **Validates: Requirements 1.3**
    """
    
    @settings(max_examples=100)
    @given(config=invalid_config_strategy)
    def test_invalid_config_raises_value_error(self, config: LangfuseConfig):
        """
        Feature: langfuse-evaluation-integration, Property 2: Invalid Configuration Raises Error
        
        Test that any configuration with enabled=True but missing credentials raises ValueError.
        """
        # Ensure we have an invalid config (enabled but missing credentials)
        assert config.enabled is True
        assert not config.public_key or not config.secret_key
        
        # validate() should raise ValueError
        with pytest.raises(ValueError) as exc_info:
            config.validate()
        
        # Error message should be descriptive
        error_message = str(exc_info.value)
        assert "Langfuse is enabled but credentials are missing" in error_message
        assert "LANGFUSE_PUBLIC_KEY" in error_message
        assert "LANGFUSE_SECRET_KEY" in error_message
    
    @settings(max_examples=100)
    @given(
        secret_key=api_key_strategy,
        host=host_strategy,
    )
    def test_missing_public_key_raises_error(
        self,
        secret_key: str,
        host: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 2: Invalid Configuration Raises Error
        
        Test that enabled config with missing public_key raises ValueError.
        """
        config = LangfuseConfig(
            enabled=True,
            public_key=None,
            secret_key=secret_key,
            host=host,
        )
        
        with pytest.raises(ValueError) as exc_info:
            config.validate()
        
        assert "credentials are missing" in str(exc_info.value)
    
    @settings(max_examples=100)
    @given(
        public_key=api_key_strategy,
        host=host_strategy,
    )
    def test_missing_secret_key_raises_error(
        self,
        public_key: str,
        host: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 2: Invalid Configuration Raises Error
        
        Test that enabled config with missing secret_key raises ValueError.
        """
        config = LangfuseConfig(
            enabled=True,
            public_key=public_key,
            secret_key=None,
            host=host,
        )
        
        with pytest.raises(ValueError) as exc_info:
            config.validate()
        
        assert "credentials are missing" in str(exc_info.value)
    
    @settings(max_examples=100)
    @given(host=host_strategy)
    def test_missing_both_keys_raises_error(self, host: str):
        """
        Feature: langfuse-evaluation-integration, Property 2: Invalid Configuration Raises Error
        
        Test that enabled config with both keys missing raises ValueError.
        """
        config = LangfuseConfig(
            enabled=True,
            public_key=None,
            secret_key=None,
            host=host,
        )
        
        with pytest.raises(ValueError) as exc_info:
            config.validate()
        
        assert "credentials are missing" in str(exc_info.value)
    
    @settings(max_examples=100)
    @given(
        secret_key=api_key_strategy,
        host=host_strategy,
    )
    def test_empty_public_key_raises_error(
        self,
        secret_key: str,
        host: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 2: Invalid Configuration Raises Error
        
        Test that enabled config with empty public_key raises ValueError.
        """
        config = LangfuseConfig(
            enabled=True,
            public_key="",
            secret_key=secret_key,
            host=host,
        )
        
        with pytest.raises(ValueError) as exc_info:
            config.validate()
        
        assert "credentials are missing" in str(exc_info.value)
    
    @settings(max_examples=100)
    @given(
        public_key=api_key_strategy,
        host=host_strategy,
    )
    def test_empty_secret_key_raises_error(
        self,
        public_key: str,
        host: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 2: Invalid Configuration Raises Error
        
        Test that enabled config with empty secret_key raises ValueError.
        """
        config = LangfuseConfig(
            enabled=True,
            public_key=public_key,
            secret_key="",
            host=host,
        )
        
        with pytest.raises(ValueError) as exc_info:
            config.validate()
        
        assert "credentials are missing" in str(exc_info.value)
    
    @settings(max_examples=100)
    @given(config=valid_enabled_config_strategy)
    def test_valid_enabled_config_does_not_raise(self, config: LangfuseConfig):
        """
        Feature: langfuse-evaluation-integration, Property 2: Invalid Configuration Raises Error
        
        Test that valid enabled configurations (with credentials) do NOT raise ValueError.
        """
        # Ensure we have a valid enabled config
        assert config.enabled is True
        assert config.public_key and len(config.public_key) > 0
        assert config.secret_key and len(config.secret_key) > 0
        
        # validate() should NOT raise
        config.validate()  # No exception expected
    
    @settings(max_examples=100)
    @given(
        public_key=st.one_of(st.none(), api_key_strategy),
        secret_key=st.one_of(st.none(), api_key_strategy),
        host=host_strategy,
    )
    def test_disabled_config_does_not_raise(
        self,
        public_key: Optional[str],
        secret_key: Optional[str],
        host: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 2: Invalid Configuration Raises Error
        
        Test that disabled configurations do NOT raise ValueError regardless of credentials.
        """
        config = LangfuseConfig(
            enabled=False,
            public_key=public_key,
            secret_key=secret_key,
            host=host,
        )
        
        # validate() should NOT raise when disabled
        config.validate()  # No exception expected


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])
