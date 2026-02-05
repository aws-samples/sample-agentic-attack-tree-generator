"""
Unit Tests for TracingManager

This module contains unit tests for the TracingManager class, verifying:
- Singleton pattern behavior
- Trace and span creation when disabled
- Proper NoOp fallback behavior
- Factory function behavior

Requirements tested:
- 2.1: Create parent trace with unique trace_id
- 2.2: Attach session_id to group related traces
- 2.3: Capture workflow metadata including timestamp
"""

import pytest
from unittest.mock import MagicMock, patch

from threatforest.tracing import (
    LangfuseConfig,
    TracingManager,
    LangfuseTrace,
    LangfuseSpan,
    NoOpTrace,
    NoOpSpan,
    NoOpTracingManager,
    get_tracing_manager,
)


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset TracingManager singleton before and after each test."""
    TracingManager.reset_instance()
    yield
    TracingManager.reset_instance()


class TestTracingManagerSingleton:
    """Tests for TracingManager singleton pattern."""
    
    def test_singleton_returns_same_instance(self):
        """Verify that TracingManager returns the same instance."""
        config = LangfuseConfig(enabled=False)
        manager1 = TracingManager(config)
        manager2 = TracingManager(config)
        
        assert manager1 is manager2
    
    def test_singleton_ignores_subsequent_config(self):
        """Verify that subsequent configs are ignored after initialization."""
        config1 = LangfuseConfig(enabled=False)
        config2 = LangfuseConfig(enabled=False, host="https://different.host.com")
        
        manager1 = TracingManager(config1)
        manager2 = TracingManager(config2)
        
        # Both should reference the same instance with config1
        assert manager1 is manager2
        assert manager1._config.host == "https://cloud.langfuse.com"
    
    def test_reset_instance_allows_new_instance(self):
        """Verify that reset_instance allows creating a new instance."""
        config1 = LangfuseConfig(enabled=False)
        manager1 = TracingManager(config1)
        
        TracingManager.reset_instance()
        
        config2 = LangfuseConfig(enabled=False, host="https://different.host.com")
        manager2 = TracingManager(config2)
        
        assert manager1 is not manager2
        assert manager2._config.host == "https://different.host.com"


class TestTracingManagerDisabled:
    """Tests for TracingManager when Langfuse is disabled."""
    
    def test_enabled_returns_false_when_disabled(self):
        """Verify enabled property returns False when disabled."""
        config = LangfuseConfig(enabled=False)
        manager = TracingManager(config)
        
        assert manager.enabled is False
    
    def test_create_trace_returns_noop_when_disabled(self):
        """Verify create_trace returns NoOpTrace when disabled."""
        config = LangfuseConfig(enabled=False)
        manager = TracingManager(config)
        
        trace = manager.create_trace("test", "session-123")
        
        assert isinstance(trace, NoOpTrace)
        assert trace.trace_id == "noop"
        assert trace.session_id == "noop"
    
    def test_create_span_returns_noop_when_disabled(self):
        """Verify create_span returns NoOpSpan when disabled."""
        config = LangfuseConfig(enabled=False)
        manager = TracingManager(config)
        trace = manager.create_trace("test", "session-123")
        
        span = manager.create_span("test_span", trace)
        
        assert isinstance(span, NoOpSpan)
        assert span.span_id == "noop"
    
    def test_flush_does_not_raise_when_disabled(self):
        """Verify flush does not raise when disabled."""
        config = LangfuseConfig(enabled=False)
        manager = TracingManager(config)
        
        # Should not raise
        manager.flush()
    
    def test_create_trace_with_metadata_returns_noop(self):
        """Verify create_trace with metadata returns NoOpTrace when disabled."""
        config = LangfuseConfig(enabled=False)
        manager = TracingManager(config)
        
        metadata = {
            "bedrock_model": "anthropic.claude-3-sonnet",
            "project_path": "/path/to/project"
        }
        trace = manager.create_trace("test", "session-123", metadata)
        
        assert isinstance(trace, NoOpTrace)


class TestGetTracingManagerFactory:
    """Tests for get_tracing_manager factory function."""
    
    def test_returns_noop_manager_when_disabled(self):
        """Verify factory returns NoOpTracingManager when disabled."""
        config = LangfuseConfig(enabled=False)
        
        manager = get_tracing_manager(config)
        
        assert isinstance(manager, NoOpTracingManager)
        assert manager.enabled is False
    
    def test_noop_manager_creates_noop_traces(self):
        """Verify NoOpTracingManager creates NoOp traces and spans."""
        config = LangfuseConfig(enabled=False)
        manager = get_tracing_manager(config)
        
        trace = manager.create_trace("test", "session-123")
        span = manager.create_span("test_span", trace)
        
        assert isinstance(trace, NoOpTrace)
        assert isinstance(span, NoOpSpan)
    
    def test_loads_config_from_env_when_not_provided(self):
        """Verify factory loads config from env when not provided."""
        with patch.dict('os.environ', {'LANGFUSE_ENABLED': 'false'}):
            manager = get_tracing_manager()
            
            assert isinstance(manager, NoOpTracingManager)


class TestLangfuseTraceWrapper:
    """Tests for LangfuseTrace wrapper class."""
    
    def test_trace_stores_ids(self):
        """Verify LangfuseTrace stores trace_id and session_id."""
        mock_langfuse_trace = MagicMock()
        
        trace = LangfuseTrace(
            langfuse_trace=mock_langfuse_trace,
            trace_id="test-trace-id",
            session_id="test-session-id"
        )
        
        assert trace.trace_id == "test-trace-id"
        assert trace.session_id == "test-session-id"
    
    def test_set_output_calls_langfuse(self):
        """Verify set_output calls underlying Langfuse trace."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        output = {"threats_generated": 5}
        trace.set_output(output)
        
        mock_langfuse_trace.update.assert_called_once_with(output=output)
    
    def test_set_status_calls_langfuse(self):
        """Verify set_status calls underlying Langfuse trace."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        trace.set_status("success")
        
        mock_langfuse_trace.update.assert_called_once_with(status_message="success")
    
    def test_set_status_with_error_includes_error_in_metadata(self):
        """Verify set_status with error includes error in metadata."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        trace.set_status("error", "Connection failed")
        
        mock_langfuse_trace.update.assert_called_once()
        call_kwargs = mock_langfuse_trace.update.call_args[1]
        assert call_kwargs["status_message"] == "error"
        assert call_kwargs["metadata"]["error"] == "Connection failed"
    
    def test_add_score_calls_langfuse(self):
        """Verify add_score calls underlying Langfuse trace."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        trace.add_score("quality", 0.85, "Good coverage")
        
        mock_langfuse_trace.score.assert_called_once_with(
            name="quality",
            value=0.85,
            comment="Good coverage"
        )
    
    def test_add_score_validates_range(self):
        """Verify add_score raises ValueError for out-of-range values."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        with pytest.raises(ValueError, match="Score value must be in range"):
            trace.add_score("quality", 1.5)
        
        with pytest.raises(ValueError, match="Score value must be in range"):
            trace.add_score("quality", -0.1)
    
    def test_add_score_accepts_boundary_values(self):
        """Verify add_score accepts 0.0 and 1.0."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        # Should not raise
        trace.add_score("min_score", 0.0)
        trace.add_score("max_score", 1.0)
    
    def test_add_metadata_calls_langfuse(self):
        """Verify add_metadata calls underlying Langfuse trace."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        trace.add_metadata("bedrock_model", "claude-3")
        
        mock_langfuse_trace.update.assert_called_once()
        call_kwargs = mock_langfuse_trace.update.call_args[1]
        assert call_kwargs["metadata"]["bedrock_model"] == "claude-3"


class TestLangfuseSpanWrapper:
    """Tests for LangfuseSpan wrapper class."""
    
    def test_span_stores_id(self):
        """Verify LangfuseSpan stores span_id."""
        mock_langfuse_span = MagicMock()
        
        span = LangfuseSpan(mock_langfuse_span, "test-span-id")
        
        assert span.span_id == "test-span-id"
    
    def test_set_input_calls_langfuse(self):
        """Verify set_input calls underlying Langfuse span."""
        mock_langfuse_span = MagicMock()
        span = LangfuseSpan(mock_langfuse_span, "span-id")
        
        input_data = {"project_path": "/path/to/project"}
        span.set_input(input_data)
        
        mock_langfuse_span.update.assert_called_once_with(input=input_data)
    
    def test_set_output_calls_langfuse(self):
        """Verify set_output calls underlying Langfuse span."""
        mock_langfuse_span = MagicMock()
        span = LangfuseSpan(mock_langfuse_span, "span-id")
        
        output_data = {"context_files": {"main.py": "..."}}
        span.set_output(output_data)
        
        mock_langfuse_span.update.assert_called_once_with(output=output_data)
    
    def test_set_metadata_calls_langfuse(self):
        """Verify set_metadata calls underlying Langfuse span."""
        mock_langfuse_span = MagicMock()
        span = LangfuseSpan(mock_langfuse_span, "span-id")
        
        metadata = {"latency_ms": 1234}
        span.set_metadata(metadata)
        
        mock_langfuse_span.update.assert_called_once_with(metadata=metadata)
    
    def test_end_calls_langfuse(self):
        """Verify end calls underlying Langfuse span."""
        mock_langfuse_span = MagicMock()
        span = LangfuseSpan(mock_langfuse_span, "span-id")
        
        span.end("success")
        
        mock_langfuse_span.update.assert_called_once_with(status_message="success")
        mock_langfuse_span.end.assert_called_once()


class TestNumericScoreValidation:
    """Tests for numeric score validation in LangfuseTrace.
    
    Validates: Requirements 4.2 - Validate score values are within allowed ranges
    """
    
    def test_add_score_accepts_valid_values(self):
        """Verify add_score accepts values in range [0.0, 1.0]."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        # Test various valid values
        trace.add_score("score1", 0.0)
        trace.add_score("score2", 0.5)
        trace.add_score("score3", 1.0)
        trace.add_score("score4", 0.33)
        trace.add_score("score5", 0.66)
        
        # All should have been called
        assert mock_langfuse_trace.score.call_count == 5
    
    def test_add_score_rejects_negative_values(self):
        """Verify add_score raises ValueError for negative values."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        with pytest.raises(ValueError, match="Score value must be in range"):
            trace.add_score("quality", -0.1)
        
        with pytest.raises(ValueError, match="Score value must be in range"):
            trace.add_score("quality", -1.0)
        
        with pytest.raises(ValueError, match="Score value must be in range"):
            trace.add_score("quality", -100.0)
    
    def test_add_score_rejects_values_above_one(self):
        """Verify add_score raises ValueError for values > 1.0."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        with pytest.raises(ValueError, match="Score value must be in range"):
            trace.add_score("quality", 1.1)
        
        with pytest.raises(ValueError, match="Score value must be in range"):
            trace.add_score("quality", 1.5)
        
        with pytest.raises(ValueError, match="Score value must be in range"):
            trace.add_score("quality", 100.0)
    
    def test_add_score_error_message_includes_value(self):
        """Verify error message includes the invalid value."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        with pytest.raises(ValueError) as exc_info:
            trace.add_score("quality", 2.5)
        
        assert "2.5" in str(exc_info.value)
    
    def test_add_score_with_comment(self):
        """Verify add_score passes comment to Langfuse."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        trace.add_score("quality", 0.85, "Good coverage")
        
        mock_langfuse_trace.score.assert_called_once_with(
            name="quality",
            value=0.85,
            comment="Good coverage"
        )
    
    def test_add_score_without_comment(self):
        """Verify add_score works without comment."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        trace.add_score("quality", 0.85)
        
        mock_langfuse_trace.score.assert_called_once_with(
            name="quality",
            value=0.85
        )


class TestCategoricalScoreValidation:
    """Tests for categorical score validation in LangfuseTrace.
    
    Validates: Requirements 4.2 - Validate categorical scores are in allowed categories
    """
    
    def test_add_categorical_score_accepts_valid_category(self):
        """Verify add_categorical_score accepts categories in allowed list."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        allowed = ["excellent", "good", "poor", "no_mapping"]
        
        trace.add_categorical_score("mapping_quality", "excellent", allowed)
        trace.add_categorical_score("mapping_quality", "good", allowed)
        trace.add_categorical_score("mapping_quality", "poor", allowed)
        trace.add_categorical_score("mapping_quality", "no_mapping", allowed)
        
        assert mock_langfuse_trace.score.call_count == 4
    
    def test_add_categorical_score_rejects_invalid_category(self):
        """Verify add_categorical_score raises ValueError for invalid categories."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        allowed = ["excellent", "good", "poor", "no_mapping"]
        
        with pytest.raises(ValueError, match="not in allowed categories"):
            trace.add_categorical_score("mapping_quality", "invalid", allowed)
        
        with pytest.raises(ValueError, match="not in allowed categories"):
            trace.add_categorical_score("mapping_quality", "great", allowed)
        
        with pytest.raises(ValueError, match="not in allowed categories"):
            trace.add_categorical_score("mapping_quality", "", allowed)
    
    def test_add_categorical_score_error_message_includes_category(self):
        """Verify error message includes the invalid category."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        allowed = ["excellent", "good", "poor"]
        
        with pytest.raises(ValueError) as exc_info:
            trace.add_categorical_score("quality", "invalid_cat", allowed)
        
        assert "invalid_cat" in str(exc_info.value)
        assert "excellent" in str(exc_info.value)
    
    def test_add_categorical_score_with_comment(self):
        """Verify add_categorical_score passes comment to Langfuse."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        allowed = ["excellent", "good", "poor"]
        trace.add_categorical_score("quality", "excellent", allowed, "Perfect match")
        
        mock_langfuse_trace.score.assert_called_once_with(
            name="quality",
            value="excellent",
            comment="Perfect match"
        )
    
    def test_add_categorical_score_without_comment(self):
        """Verify add_categorical_score works without comment."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        allowed = ["excellent", "good", "poor"]
        trace.add_categorical_score("quality", "good", allowed)
        
        mock_langfuse_trace.score.assert_called_once_with(
            name="quality",
            value="good"
        )
    
    def test_add_categorical_score_case_sensitive(self):
        """Verify categorical score validation is case-sensitive."""
        mock_langfuse_trace = MagicMock()
        trace = LangfuseTrace(mock_langfuse_trace, "trace-id", "session-id")
        
        allowed = ["excellent", "good", "poor"]
        
        # These should fail because case doesn't match
        with pytest.raises(ValueError, match="not in allowed categories"):
            trace.add_categorical_score("quality", "Excellent", allowed)
        
        with pytest.raises(ValueError, match="not in allowed categories"):
            trace.add_categorical_score("quality", "GOOD", allowed)


class TestNoOpScoreValidation:
    """Tests for NoOpTrace score methods.
    
    Verifies that NoOpTrace accepts all score operations without validation.
    """
    
    def test_noop_add_score_accepts_any_value(self):
        """Verify NoOpTrace.add_score accepts any value without raising."""
        trace = NoOpTrace()
        
        # Should not raise for any value
        trace.add_score("quality", 0.5)
        trace.add_score("quality", -1.0)  # Invalid but no-op
        trace.add_score("quality", 100.0)  # Invalid but no-op
    
    def test_noop_add_categorical_score_accepts_any_category(self):
        """Verify NoOpTrace.add_categorical_score accepts any category without raising."""
        trace = NoOpTrace()
        
        allowed = ["excellent", "good", "poor"]
        
        # Should not raise for any category
        trace.add_categorical_score("quality", "excellent", allowed)
        trace.add_categorical_score("quality", "invalid", allowed)  # Invalid but no-op
        trace.add_categorical_score("quality", "", [])  # Invalid but no-op


class TestTracingManagerWithMockedLangfuse:
    """Tests for TracingManager with mocked Langfuse client."""
    
    def test_creates_langfuse_client_when_enabled(self):
        """Verify Langfuse client is created when enabled."""
        mock_langfuse_class = MagicMock()
        mock_client = MagicMock()
        mock_langfuse_class.return_value = mock_client
        
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test",
            host="https://test.langfuse.com"
        )
        
        # Create a mock langfuse module
        mock_langfuse_module = MagicMock()
        mock_langfuse_module.Langfuse = mock_langfuse_class
        
        # Patch the import inside _init_client
        with patch.dict('sys.modules', {'langfuse': mock_langfuse_module}):
            manager = TracingManager(config)
        
        assert manager.enabled is True
    
    def test_raises_import_error_when_langfuse_not_installed(self):
        """Verify ImportError is raised when langfuse is not installed."""
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test"
        )
        
        # Simulate langfuse not being installed
        with patch.dict('sys.modules', {'langfuse': None}):
            with pytest.raises(ImportError, match="langfuse"):
                TracingManager(config)
    
    def test_validates_config_when_enabled(self):
        """Verify config is validated when enabled."""
        config = LangfuseConfig(
            enabled=True,
            public_key=None,  # Missing credentials
            secret_key=None
        )
        
        with pytest.raises(ValueError, match="credentials are missing"):
            TracingManager(config)
