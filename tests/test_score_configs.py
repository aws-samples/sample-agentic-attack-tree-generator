"""
Tests for Score Configuration Registration

Tests the ScoreConfigRegistry class which registers ThreatForest score
definitions with Langfuse's score_configs API.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from typing import List

from threatforest.tracing.score_configs import (
    RegisteredScoreConfig,
    ScoreConfigRegistry,
    get_score_config_registry,
    reset_score_config_registry,
)
from threatforest.tracing.config import LangfuseConfig
from threatforest.tracing.scores import (
    ScoreDefinition,
    ScoreType,
    THREAT_STATEMENT_SCORES,
    ATTACK_TREE_SCORES,
    TTP_MAPPING_SCORES,
    TTP_SCORE_VALUES,
)


class TestRegisteredScoreConfig:
    """Tests for RegisteredScoreConfig dataclass."""
    
    def test_create_registered_config(self):
        """Test creating a RegisteredScoreConfig."""
        config = RegisteredScoreConfig(
            name="test_score",
            config_id="cfg-123",
            data_type="NUMERIC",
            is_archived=False
        )
        
        assert config.name == "test_score"
        assert config.config_id == "cfg-123"
        assert config.data_type == "NUMERIC"
        assert config.is_archived is False
    
    def test_default_is_archived(self):
        """Test that is_archived defaults to False."""
        config = RegisteredScoreConfig(
            name="test",
            config_id="cfg-456",
            data_type="CATEGORICAL"
        )
        
        assert config.is_archived is False


class TestScoreConfigRegistryDisabled:
    """Tests for ScoreConfigRegistry when Langfuse is disabled."""
    
    def test_disabled_registry_returns_none(self):
        """Test that disabled registry returns None for registrations."""
        config = LangfuseConfig(enabled=False)
        registry = ScoreConfigRegistry(config)
        
        score_def = ScoreDefinition(
            name="test",
            score_type=ScoreType.NUMERIC,
            description="Test score"
        )
        
        result = registry.register_score_definition(score_def)
        assert result is None
    
    def test_disabled_registry_returns_empty_dict(self):
        """Test that disabled registry returns empty dict for register_all."""
        config = LangfuseConfig(enabled=False)
        registry = ScoreConfigRegistry(config)
        
        result = registry.register_all_score_definitions()
        assert result == {}
    
    def test_get_config_id_returns_none_when_disabled(self):
        """Test get_config_id returns None when disabled."""
        config = LangfuseConfig(enabled=False)
        registry = ScoreConfigRegistry(config)
        
        assert registry.get_config_id("any_score") is None
    
    def test_is_registered_returns_false_when_disabled(self):
        """Test is_registered returns False when disabled."""
        config = LangfuseConfig(enabled=False)
        registry = ScoreConfigRegistry(config)
        
        assert registry.is_registered("any_score") is False


class TestScoreConfigRegistryEnabled:
    """Tests for ScoreConfigRegistry when Langfuse is enabled."""
    
    @pytest.fixture
    def mock_langfuse_client(self):
        """Create a mock Langfuse client."""
        mock_client = MagicMock()
        mock_client.api.score_configs.create.return_value = Mock(id="cfg-new-123")
        mock_client.api.score_configs.get.return_value = Mock(data=[])
        return mock_client
    
    @pytest.fixture
    def enabled_config(self):
        """Create an enabled Langfuse config."""
        return LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",
            host="https://test.langfuse.com"
        )
    
    @patch("threatforest.tracing.score_configs.CreateScoreConfigRequest")
    @patch("threatforest.tracing.score_configs.Langfuse")
    def test_register_numeric_score(self, mock_langfuse_class, mock_request_class, enabled_config, mock_langfuse_client):
        """Test registering a numeric score definition."""
        mock_langfuse_class.return_value = mock_langfuse_client
        mock_request_instance = MagicMock()
        mock_request_class.return_value = mock_request_instance
        
        registry = ScoreConfigRegistry(enabled_config)
        
        score_def = ScoreDefinition(
            name="quality",
            score_type=ScoreType.NUMERIC,
            description="Quality score",
            min_value=0.0,
            max_value=1.0
        )
        
        result = registry.register_score_definition(score_def)
        
        assert result is not None
        assert result.name == "quality"
        assert result.config_id == "cfg-new-123"
        
        # Verify CreateScoreConfigRequest was called correctly
        mock_request_class.assert_called_once()
        call_kwargs = mock_request_class.call_args.kwargs
        assert call_kwargs["name"] == "quality"
        assert call_kwargs["min_value"] == 0.0
        assert call_kwargs["max_value"] == 1.0
        
        # Verify API was called with the request object
        mock_langfuse_client.api.score_configs.create.assert_called_once_with(
            request=mock_request_instance
        )
    
    @patch("threatforest.tracing.score_configs.ConfigCategory")
    @patch("threatforest.tracing.score_configs.CreateScoreConfigRequest")
    @patch("threatforest.tracing.score_configs.Langfuse")
    def test_register_categorical_score(self, mock_langfuse_class, mock_request_class, mock_config_category, enabled_config, mock_langfuse_client):
        """Test registering a categorical score definition."""
        mock_langfuse_class.return_value = mock_langfuse_client
        mock_request_instance = MagicMock()
        mock_request_class.return_value = mock_request_instance
        # Make ConfigCategory return a mock that we can track
        mock_config_category.side_effect = lambda label, value: MagicMock(label=label, value=value)
        
        registry = ScoreConfigRegistry(enabled_config)
        
        score_def = ScoreDefinition(
            name="mapping_quality",
            score_type=ScoreType.CATEGORICAL,
            description="TTP mapping quality",
            categories=["excellent", "good", "poor", "no_mapping"]
        )
        
        result = registry.register_score_definition(score_def)
        
        assert result is not None
        assert result.name == "mapping_quality"
        
        # Verify CreateScoreConfigRequest was called with categories
        mock_request_class.assert_called_once()
        call_kwargs = mock_request_class.call_args.kwargs
        assert "categories" in call_kwargs
        categories = call_kwargs["categories"]
        assert len(categories) == 4
        
        # Verify ConfigCategory was called for each category
        assert mock_config_category.call_count == 4
        
        # Verify TTP_SCORE_VALUES mapping was used
        calls = mock_config_category.call_args_list
        excellent_call = next(c for c in calls if c.kwargs.get("label") == "excellent")
        assert excellent_call.kwargs["value"] == TTP_SCORE_VALUES["excellent"]
    
    @patch("threatforest.tracing.score_configs.CreateScoreConfigRequest")
    @patch("threatforest.tracing.score_configs.Langfuse")
    def test_register_with_prefix(self, mock_langfuse_class, mock_request_class, enabled_config, mock_langfuse_client):
        """Test registering a score with a prefix."""
        mock_langfuse_class.return_value = mock_langfuse_client
        mock_request_instance = MagicMock()
        mock_request_class.return_value = mock_request_instance
        
        registry = ScoreConfigRegistry(enabled_config)
        
        score_def = ScoreDefinition(
            name="quality",
            score_type=ScoreType.NUMERIC,
            description="Quality score"
        )
        
        result = registry.register_score_definition(score_def, prefix="threat_")
        
        assert result is not None
        assert result.name == "threat_quality"
        
        call_kwargs = mock_request_class.call_args.kwargs
        assert call_kwargs["name"] == "threat_quality"
    
    @patch("threatforest.tracing.score_configs.Langfuse")
    def test_skip_existing_config(self, mock_langfuse_class, enabled_config):
        """Test that existing configs are not re-created."""
        mock_client = MagicMock()
        
        # Simulate existing config in Langfuse
        # Note: Use MagicMock and set attributes explicitly because Mock(name=...) 
        # sets the mock's internal name, not a 'name' attribute
        existing_config = MagicMock()
        existing_config.name = "quality"
        existing_config.id = "cfg-existing-456"
        existing_config.data_type = "NUMERIC"
        existing_config.is_archived = False
        
        mock_client.api.score_configs.get.return_value = Mock(data=[existing_config])
        mock_langfuse_class.return_value = mock_client
        
        registry = ScoreConfigRegistry(enabled_config)
        
        score_def = ScoreDefinition(
            name="quality",
            score_type=ScoreType.NUMERIC,
            description="Quality score"
        )
        
        result = registry.register_score_definition(score_def)
        
        assert result is not None
        assert result.config_id == "cfg-existing-456"
        
        # Verify create was NOT called
        mock_client.api.score_configs.create.assert_not_called()
    
    @patch("threatforest.tracing.score_configs.CreateScoreConfigRequest")
    @patch("threatforest.tracing.score_configs.Langfuse")
    def test_cache_registered_config(self, mock_langfuse_class, mock_request_class, enabled_config, mock_langfuse_client):
        """Test that registered configs are cached locally."""
        mock_langfuse_class.return_value = mock_langfuse_client
        mock_request_instance = MagicMock()
        mock_request_class.return_value = mock_request_instance
        
        registry = ScoreConfigRegistry(enabled_config)
        
        score_def = ScoreDefinition(
            name="quality",
            score_type=ScoreType.NUMERIC,
            description="Quality score"
        )
        
        # First registration
        result1 = registry.register_score_definition(score_def)
        
        # Second registration should use cache
        result2 = registry.register_score_definition(score_def)
        
        assert result1 is result2
        
        # Create should only be called once
        assert mock_langfuse_client.api.score_configs.create.call_count == 1
    
    @patch("threatforest.tracing.score_configs.CreateScoreConfigRequest")
    @patch("threatforest.tracing.score_configs.Langfuse")
    def test_get_config_id(self, mock_langfuse_class, mock_request_class, enabled_config, mock_langfuse_client):
        """Test retrieving config ID by name."""
        mock_langfuse_class.return_value = mock_langfuse_client
        mock_request_instance = MagicMock()
        mock_request_class.return_value = mock_request_instance
        
        registry = ScoreConfigRegistry(enabled_config)
        
        score_def = ScoreDefinition(
            name="quality",
            score_type=ScoreType.NUMERIC,
            description="Quality score"
        )
        
        registry.register_score_definition(score_def)
        
        config_id = registry.get_config_id("quality")
        assert config_id == "cfg-new-123"
        
        # Non-existent should return None
        assert registry.get_config_id("nonexistent") is None
    
    @patch("threatforest.tracing.score_configs.CreateScoreConfigRequest")
    @patch("threatforest.tracing.score_configs.Langfuse")
    def test_is_registered(self, mock_langfuse_class, mock_request_class, enabled_config, mock_langfuse_client):
        """Test checking if a score is registered."""
        mock_langfuse_class.return_value = mock_langfuse_client
        mock_request_instance = MagicMock()
        mock_request_class.return_value = mock_request_instance
        
        registry = ScoreConfigRegistry(enabled_config)
        
        score_def = ScoreDefinition(
            name="quality",
            score_type=ScoreType.NUMERIC,
            description="Quality score"
        )
        
        assert registry.is_registered("quality") is False
        
        registry.register_score_definition(score_def)
        
        assert registry.is_registered("quality") is True
    
    @patch("threatforest.tracing.score_configs.CreateScoreConfigRequest")
    @patch("threatforest.tracing.score_configs.Langfuse")
    def test_get_registered_configs(self, mock_langfuse_class, mock_request_class, enabled_config, mock_langfuse_client):
        """Test getting all registered configs."""
        mock_langfuse_class.return_value = mock_langfuse_client
        mock_request_instance = MagicMock()
        mock_request_class.return_value = mock_request_instance
        
        registry = ScoreConfigRegistry(enabled_config)
        
        score_def = ScoreDefinition(
            name="quality",
            score_type=ScoreType.NUMERIC,
            description="Quality score"
        )
        
        registry.register_score_definition(score_def)
        
        configs = registry.get_registered_configs()
        
        assert "quality" in configs
        assert configs["quality"].config_id == "cfg-new-123"
        
        # Should return a copy
        configs["quality"] = None
        assert registry.get_registered_configs()["quality"] is not None


class TestRegisterAllScoreDefinitions:
    """Tests for registering all ThreatForest score definitions."""
    
    @patch("threatforest.tracing.score_configs.ConfigCategory")
    @patch("threatforest.tracing.score_configs.CreateScoreConfigRequest")
    @patch("threatforest.tracing.score_configs.Langfuse")
    def test_register_all_with_prefix(self, mock_langfuse_class, mock_request_class, mock_config_category):
        """Test registering all scores with category prefixes."""
        mock_client = MagicMock()
        mock_client.api.score_configs.create.return_value = Mock(id="cfg-123")
        mock_client.api.score_configs.get.return_value = Mock(data=[])
        mock_langfuse_class.return_value = mock_client
        mock_request_instance = MagicMock()
        mock_request_class.return_value = mock_request_instance
        mock_config_category.side_effect = lambda label, value: MagicMock(label=label, value=value)
        
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",
            host="https://test.langfuse.com"
        )
        
        registry = ScoreConfigRegistry(config)
        result = registry.register_all_score_definitions(include_prefix=True)
        
        # Check that prefixed names are used
        expected_threat_scores = [f"threat_{s.name}" for s in THREAT_STATEMENT_SCORES]
        expected_attack_scores = [f"attack_tree_{s.name}" for s in ATTACK_TREE_SCORES]
        expected_ttp_scores = [f"ttp_{s.name}" for s in TTP_MAPPING_SCORES]
        
        for name in expected_threat_scores:
            assert name in result, f"Missing threat score: {name}"
        
        for name in expected_attack_scores:
            assert name in result, f"Missing attack tree score: {name}"
        
        for name in expected_ttp_scores:
            assert name in result, f"Missing TTP score: {name}"
    
    @patch("threatforest.tracing.score_configs.ConfigCategory")
    @patch("threatforest.tracing.score_configs.CreateScoreConfigRequest")
    @patch("threatforest.tracing.score_configs.Langfuse")
    def test_register_all_without_prefix(self, mock_langfuse_class, mock_request_class, mock_config_category):
        """Test registering all scores without prefixes."""
        mock_client = MagicMock()
        mock_client.api.score_configs.create.return_value = Mock(id="cfg-123")
        mock_client.api.score_configs.get.return_value = Mock(data=[])
        mock_langfuse_class.return_value = mock_client
        mock_request_instance = MagicMock()
        mock_request_class.return_value = mock_request_instance
        mock_config_category.side_effect = lambda label, value: MagicMock(label=label, value=value)
        
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",
            host="https://test.langfuse.com"
        )
        
        registry = ScoreConfigRegistry(config)
        result = registry.register_all_score_definitions(include_prefix=False)
        
        # Check that unprefixed names are used
        for score_def in THREAT_STATEMENT_SCORES:
            assert score_def.name in result
        
        for score_def in ATTACK_TREE_SCORES:
            assert score_def.name in result


class TestSyncWithLangfuse:
    """Tests for syncing with existing Langfuse configs."""
    
    @patch("threatforest.tracing.score_configs.Langfuse")
    def test_sync_populates_registry(self, mock_langfuse_class):
        """Test that sync populates registry with existing configs."""
        mock_client = MagicMock()
        
        # Note: Use MagicMock and set attributes explicitly because Mock(name=...) 
        # sets the mock's internal name, not a 'name' attribute
        existing_config_1 = MagicMock()
        existing_config_1.name = "existing_score_1"
        existing_config_1.id = "cfg-1"
        existing_config_1.data_type = "NUMERIC"
        existing_config_1.is_archived = False
        
        existing_config_2 = MagicMock()
        existing_config_2.name = "existing_score_2"
        existing_config_2.id = "cfg-2"
        existing_config_2.data_type = "CATEGORICAL"
        existing_config_2.is_archived = True
        
        mock_client.api.score_configs.get.return_value = Mock(data=[existing_config_1, existing_config_2])
        mock_langfuse_class.return_value = mock_client
        
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",
            host="https://test.langfuse.com"
        )
        
        registry = ScoreConfigRegistry(config)
        registry.sync_with_langfuse()
        
        assert registry.is_registered("existing_score_1")
        assert registry.is_registered("existing_score_2")
        assert registry.get_config_id("existing_score_1") == "cfg-1"
        assert registry.get_config_id("existing_score_2") == "cfg-2"


class TestSingletonPattern:
    """Tests for the singleton pattern."""
    
    def setup_method(self):
        """Reset singleton before each test."""
        reset_score_config_registry()
    
    def teardown_method(self):
        """Reset singleton after each test."""
        reset_score_config_registry()
    
    def test_get_score_config_registry_returns_singleton(self):
        """Test that get_score_config_registry returns the same instance."""
        config = LangfuseConfig(enabled=False)
        
        registry1 = get_score_config_registry(config)
        registry2 = get_score_config_registry()
        
        assert registry1 is registry2
    
    def test_reset_clears_singleton(self):
        """Test that reset_score_config_registry clears the singleton."""
        config = LangfuseConfig(enabled=False)
        
        registry1 = get_score_config_registry(config)
        reset_score_config_registry()
        registry2 = get_score_config_registry(config)
        
        assert registry1 is not registry2


class TestErrorHandling:
    """Tests for error handling in ScoreConfigRegistry."""
    
    @patch("threatforest.tracing.score_configs.UpdateScoreConfigRequest")
    @patch("threatforest.tracing.score_configs.ConfigCategory")
    @patch("threatforest.tracing.score_configs.CreateScoreConfigRequest")
    @patch("threatforest.tracing.score_configs.Langfuse")
    def test_archives_and_recreates_on_type_mismatch(
        self, mock_langfuse_class, mock_request_class, mock_config_category, mock_update_request_class
    ):
        """Test that a type mismatch (NUMERIC→CATEGORICAL) archives old and creates new."""
        mock_client = MagicMock()
        
        # Simulate existing NUMERIC config in Langfuse
        existing_config = MagicMock()
        existing_config.name = "threat_overall_quality"
        existing_config.id = "cfg-old-numeric"
        existing_config.data_type = "NUMERIC"
        existing_config.is_archived = False
        
        mock_client.api.score_configs.get.return_value = Mock(data=[existing_config])
        mock_client.api.score_configs.create.return_value = Mock(id="cfg-new-categorical")
        mock_langfuse_class.return_value = mock_client
        mock_request_instance = MagicMock()
        mock_request_class.return_value = mock_request_instance
        mock_update_instance = MagicMock()
        mock_update_request_class.return_value = mock_update_instance
        mock_config_category.side_effect = lambda label, value: MagicMock(label=label, value=value)
        
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",
            host="https://test.langfuse.com"
        )
        
        registry = ScoreConfigRegistry(config)
        
        # Register a CATEGORICAL score with the same name
        score_def = ScoreDefinition(
            name="overall_quality",
            score_type=ScoreType.CATEGORICAL,
            description="Overall quality",
            categories=["excellent", "good", "acceptable", "poor", "unacceptable"]
        )
        
        result = registry.register_score_definition(score_def, prefix="threat_")
        
        # Should have archived the old config
        mock_update_request_class.assert_called_once_with(is_archived=True)
        mock_client.api.score_configs.update.assert_called_once_with(
            config_id="cfg-old-numeric", request=mock_update_instance
        )
        
        # Should have created a new config
        mock_client.api.score_configs.create.assert_called_once()
        
        # Result should be the new config
        assert result is not None
        assert result.config_id == "cfg-new-categorical"
        assert result.name == "threat_overall_quality"
    
    @patch("threatforest.tracing.score_configs.Langfuse")
    def test_skips_archived_configs_in_lookup(self, mock_langfuse_class):
        """Test that archived configs are skipped when looking up existing configs."""
        mock_client = MagicMock()
        
        # Simulate archived config in Langfuse
        archived_config = MagicMock()
        archived_config.name = "quality"
        archived_config.id = "cfg-archived"
        archived_config.data_type = "NUMERIC"
        archived_config.is_archived = True
        
        mock_client.api.score_configs.get.return_value = Mock(data=[archived_config])
        mock_client.api.score_configs.create.return_value = Mock(id="cfg-new")
        mock_langfuse_class.return_value = mock_client
        
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",
            host="https://test.langfuse.com"
        )
        
        registry = ScoreConfigRegistry(config)
        
        # _get_existing_config should skip archived
        result = registry._get_existing_config("quality")
        assert result is None

    @patch("threatforest.tracing.score_configs.CreateScoreConfigRequest")
    @patch("threatforest.tracing.score_configs.Langfuse")
    def test_handles_api_error_gracefully(self, mock_langfuse_class, mock_request_class):
        """Test that API errors are handled gracefully."""
        mock_client = MagicMock()
        mock_client.api.score_configs.create.side_effect = Exception("API Error")
        mock_client.api.score_configs.get.return_value = Mock(data=[])
        mock_langfuse_class.return_value = mock_client
        mock_request_instance = MagicMock()
        mock_request_class.return_value = mock_request_instance
        
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",
            host="https://test.langfuse.com"
        )
        
        registry = ScoreConfigRegistry(config)
        
        score_def = ScoreDefinition(
            name="quality",
            score_type=ScoreType.NUMERIC,
            description="Quality score"
        )
        
        # Should return None instead of raising
        result = registry.register_score_definition(score_def)
        assert result is None
    
    @patch("threatforest.tracing.score_configs.Langfuse", side_effect=ImportError("langfuse not installed"))
    def test_handles_missing_langfuse_package(self, mock_langfuse_class):
        """Test handling when langfuse package is not installed."""
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",
            host="https://test.langfuse.com"
        )
        
        # Should not raise, just log warning and set client to None
        registry = ScoreConfigRegistry(config)
        assert registry._client is None
