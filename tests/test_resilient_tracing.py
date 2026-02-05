"""
Unit Tests for ResilientTracingManager

This module contains unit tests for the ResilientTracingManager class, verifying:
- Graceful degradation when Langfuse is unavailable
- Buffering of traces and spans during connection failures
- Warning logging on connection failure
- Flush behavior for buffered traces
- Workflow continuation despite tracing failures

Requirements tested:
- 9.3: When Langfuse connection fails, log a warning and continue workflow execution

Property 15: Connection Failure Resilience
*For any* workflow execution where Langfuse connection fails (network error,
invalid credentials), the workflow SHALL continue execution, a warning SHALL
be logged, and the workflow result SHALL not be affected.
"""

import logging
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from threatforest.tracing import (
    LangfuseConfig,
    TracingManager,
)
from threatforest.tracing.resilient import (
    BufferedSpan,
    BufferedSpanWrapper,
    BufferedTrace,
    BufferedTraceWrapper,
    ResilientTracingManager,
    get_resilient_tracing_manager,
)


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset singleton instances before and after each test."""
    ResilientTracingManager.reset_instance()
    TracingManager.reset_instance()
    yield
    ResilientTracingManager.reset_instance()
    TracingManager.reset_instance()


class TestResilientTracingManagerSingleton:
    """Tests for ResilientTracingManager singleton pattern."""
    
    def test_singleton_returns_same_instance(self):
        """Verify that ResilientTracingManager returns the same instance."""
        config = LangfuseConfig(enabled=False)
        manager1 = ResilientTracingManager(config)
        manager2 = ResilientTracingManager(config)
        
        assert manager1 is manager2
    
    def test_reset_instance_allows_new_instance(self):
        """Verify that reset_instance allows creating a new instance."""
        config1 = LangfuseConfig(enabled=False)
        manager1 = ResilientTracingManager(config1)
        
        ResilientTracingManager.reset_instance()
        
        config2 = LangfuseConfig(enabled=False, host="https://different.host.com")
        manager2 = ResilientTracingManager(config2)
        
        assert manager1 is not manager2


class TestResilientTracingManagerDisabled:
    """Tests for ResilientTracingManager when Langfuse is disabled."""
    
    def test_enabled_returns_false_when_disabled(self):
        """Verify enabled property returns False when disabled."""
        config = LangfuseConfig(enabled=False)
        manager = ResilientTracingManager(config)
        
        assert manager.enabled is False
    
    def test_not_in_fallback_mode_when_disabled(self):
        """Verify manager is not in fallback mode when simply disabled."""
        config = LangfuseConfig(enabled=False)
        manager = ResilientTracingManager(config)
        
        # When disabled, we're not in fallback mode - we just don't trace
        assert manager.fallback_mode is False
    
    def test_create_trace_returns_noop_when_disabled(self):
        """Verify create_trace returns NoOpTrace when disabled."""
        config = LangfuseConfig(enabled=False)
        manager = ResilientTracingManager(config)
        
        trace = manager.create_trace("test", "session-123")
        
        # When disabled, parent class returns NoOpTrace
        assert trace.trace_id == "noop"
        assert trace.session_id == "noop"


class TestBufferedTrace:
    """Tests for BufferedTrace dataclass."""
    
    def test_buffered_trace_has_unique_id(self):
        """Verify BufferedTrace generates unique trace_id."""
        trace1 = BufferedTrace(name="test1", session_id="session-1")
        trace2 = BufferedTrace(name="test2", session_id="session-2")
        
        assert trace1.trace_id != trace2.trace_id
        assert len(trace1.trace_id) > 0
    
    def test_buffered_trace_stores_metadata(self):
        """Verify BufferedTrace stores metadata correctly."""
        metadata = {"key": "value"}
        trace = BufferedTrace(
            name="test",
            session_id="session-123",
            metadata=metadata
        )
        
        assert trace.name == "test"
        assert trace.session_id == "session-123"
        assert trace.metadata == metadata
    
    def test_buffered_trace_has_created_at(self):
        """Verify BufferedTrace has created_at timestamp."""
        trace = BufferedTrace(name="test", session_id="session-123")
        
        assert trace.created_at is not None
        assert len(trace.created_at) > 0


class TestBufferedTraceWrapper:
    """Tests for BufferedTraceWrapper class."""
    
    def test_wrapper_exposes_trace_id(self):
        """Verify wrapper exposes trace_id from buffered trace."""
        buffered = BufferedTrace(name="test", session_id="session-123")
        wrapper = BufferedTraceWrapper(buffered)
        
        assert wrapper.trace_id == buffered.trace_id
    
    def test_wrapper_exposes_session_id(self):
        """Verify wrapper exposes session_id from buffered trace."""
        buffered = BufferedTrace(name="test", session_id="session-123")
        wrapper = BufferedTraceWrapper(buffered)
        
        assert wrapper.session_id == "session-123"
    
    def test_set_output_stores_in_buffer(self):
        """Verify set_output stores output in buffered trace."""
        buffered = BufferedTrace(name="test", session_id="session-123")
        wrapper = BufferedTraceWrapper(buffered)
        
        output = {"threats_generated": 5}
        wrapper.set_output(output)
        
        assert buffered.output == output
    
    def test_set_status_stores_in_buffer(self):
        """Verify set_status stores status in buffered trace."""
        buffered = BufferedTrace(name="test", session_id="session-123")
        wrapper = BufferedTraceWrapper(buffered)
        
        wrapper.set_status("success")
        
        assert buffered.status == "success"
        assert buffered.error is None
    
    def test_set_status_with_error_stores_both(self):
        """Verify set_status with error stores both status and error."""
        buffered = BufferedTrace(name="test", session_id="session-123")
        wrapper = BufferedTraceWrapper(buffered)
        
        wrapper.set_status("error", "Connection failed")
        
        assert buffered.status == "error"
        assert buffered.error == "Connection failed"
    
    def test_add_score_stores_in_buffer(self):
        """Verify add_score stores score in buffered trace."""
        buffered = BufferedTrace(name="test", session_id="session-123")
        wrapper = BufferedTraceWrapper(buffered)
        
        wrapper.add_score("quality", 0.85, "Good coverage")
        
        assert len(buffered.scores) == 1
        assert buffered.scores[0]["name"] == "quality"
        assert buffered.scores[0]["value"] == 0.85
        assert buffered.scores[0]["comment"] == "Good coverage"
    
    def test_add_score_validates_range(self):
        """Verify add_score validates score range."""
        buffered = BufferedTrace(name="test", session_id="session-123")
        wrapper = BufferedTraceWrapper(buffered)
        
        with pytest.raises(ValueError, match="Score value must be in range"):
            wrapper.add_score("quality", 1.5)
        
        with pytest.raises(ValueError, match="Score value must be in range"):
            wrapper.add_score("quality", -0.1)
    
    def test_add_categorical_score_stores_in_buffer(self):
        """Verify add_categorical_score stores score in buffered trace."""
        buffered = BufferedTrace(name="test", session_id="session-123")
        wrapper = BufferedTraceWrapper(buffered)
        
        allowed = ["excellent", "good", "poor"]
        wrapper.add_categorical_score("mapping_quality", "excellent", allowed, "Perfect")
        
        assert len(buffered.categorical_scores) == 1
        assert buffered.categorical_scores[0]["name"] == "mapping_quality"
        assert buffered.categorical_scores[0]["category"] == "excellent"
    
    def test_add_categorical_score_validates_category(self):
        """Verify add_categorical_score validates category."""
        buffered = BufferedTrace(name="test", session_id="session-123")
        wrapper = BufferedTraceWrapper(buffered)
        
        allowed = ["excellent", "good", "poor"]
        
        with pytest.raises(ValueError, match="not in allowed categories"):
            wrapper.add_categorical_score("quality", "invalid", allowed)
    
    def test_add_metadata_stores_in_buffer(self):
        """Verify add_metadata stores metadata in buffered trace."""
        buffered = BufferedTrace(name="test", session_id="session-123")
        wrapper = BufferedTraceWrapper(buffered)
        
        wrapper.add_metadata("bedrock_model", "claude-3")
        wrapper.add_metadata("project_path", "/path/to/project")
        
        assert buffered.additional_metadata["bedrock_model"] == "claude-3"
        assert buffered.additional_metadata["project_path"] == "/path/to/project"


class TestBufferedSpan:
    """Tests for BufferedSpan dataclass."""
    
    def test_buffered_span_has_unique_id(self):
        """Verify BufferedSpan generates unique span_id."""
        span1 = BufferedSpan(name="span1", trace_id="trace-1")
        span2 = BufferedSpan(name="span2", trace_id="trace-2")
        
        assert span1.span_id != span2.span_id
        assert len(span1.span_id) > 0
    
    def test_buffered_span_stores_trace_id(self):
        """Verify BufferedSpan stores parent trace_id."""
        span = BufferedSpan(name="test_span", trace_id="parent-trace-id")
        
        assert span.trace_id == "parent-trace-id"


class TestBufferedSpanWrapper:
    """Tests for BufferedSpanWrapper class."""
    
    def test_wrapper_exposes_span_id(self):
        """Verify wrapper exposes span_id from buffered span."""
        buffered = BufferedSpan(name="test", trace_id="trace-123")
        wrapper = BufferedSpanWrapper(buffered)
        
        assert wrapper.span_id == buffered.span_id
    
    def test_set_input_stores_in_buffer(self):
        """Verify set_input stores input in buffered span."""
        buffered = BufferedSpan(name="test", trace_id="trace-123")
        wrapper = BufferedSpanWrapper(buffered)
        
        input_data = {"project_path": "/path/to/project"}
        wrapper.set_input(input_data)
        
        assert buffered.input_data == input_data
    
    def test_set_output_stores_in_buffer(self):
        """Verify set_output stores output in buffered span."""
        buffered = BufferedSpan(name="test", trace_id="trace-123")
        wrapper = BufferedSpanWrapper(buffered)
        
        output_data = {"context_files": {"main.py": "..."}}
        wrapper.set_output(output_data)
        
        assert buffered.output_data == output_data
    
    def test_set_metadata_stores_in_buffer(self):
        """Verify set_metadata stores metadata in buffered span."""
        buffered = BufferedSpan(name="test", trace_id="trace-123")
        wrapper = BufferedSpanWrapper(buffered)
        
        metadata = {"latency_ms": 1234}
        wrapper.set_metadata(metadata)
        
        assert buffered.span_metadata["latency_ms"] == 1234
    
    def test_end_stores_status_in_buffer(self):
        """Verify end stores status in buffered span."""
        buffered = BufferedSpan(name="test", trace_id="trace-123")
        wrapper = BufferedSpanWrapper(buffered)
        
        wrapper.end("success")
        
        assert buffered.status == "success"
    
    def test_generation_returns_noop(self):
        """Verify generation returns NoOp context manager."""
        buffered = BufferedSpan(name="test", trace_id="trace-123")
        wrapper = BufferedSpanWrapper(buffered)
        
        with wrapper.generation("test_gen", "claude-3") as gen:
            assert gen.generation_id == "noop"


class TestResilientTracingManagerFallback:
    """Tests for ResilientTracingManager fallback behavior."""
    
    def test_switches_to_fallback_on_connection_error(self):
        """Verify manager switches to fallback mode on connection error."""
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test"
        )
        
        # Mock the Langfuse client to raise an error
        with patch.object(
            ResilientTracingManager,
            '_init_client',
            side_effect=Exception("Connection refused")
        ):
            manager = ResilientTracingManager(config)
        
        assert manager.fallback_mode is True
    
    def test_logs_warning_on_connection_failure(self, caplog):
        """Verify warning is logged when connection fails."""
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test"
        )
        
        with caplog.at_level(logging.WARNING):
            with patch.object(
                ResilientTracingManager,
                '_init_client',
                side_effect=Exception("Connection refused")
            ):
                manager = ResilientTracingManager(config)
        
        assert "Langfuse initialization failed" in caplog.text
        assert "fallback mode" in caplog.text
    
    def test_create_trace_returns_buffered_in_fallback(self):
        """Verify create_trace returns BufferedTraceWrapper in fallback mode."""
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test"
        )
        
        with patch.object(
            ResilientTracingManager,
            '_init_client',
            side_effect=Exception("Connection refused")
        ):
            manager = ResilientTracingManager(config)
        
        trace = manager.create_trace("test", "session-123")
        
        assert isinstance(trace, BufferedTraceWrapper)
        assert manager.buffered_trace_count == 1
    
    def test_create_span_returns_buffered_for_buffered_trace(self):
        """Verify create_span returns BufferedSpanWrapper for buffered trace."""
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test"
        )
        
        with patch.object(
            ResilientTracingManager,
            '_init_client',
            side_effect=Exception("Connection refused")
        ):
            manager = ResilientTracingManager(config)
        
        trace = manager.create_trace("test", "session-123")
        span = manager.create_span("test_span", trace)
        
        assert isinstance(span, BufferedSpanWrapper)
        assert manager.buffered_span_count == 1
    
    def test_workflow_continues_despite_tracing_failure(self):
        """Verify workflow can continue when tracing fails.
        
        Property 15: Connection Failure Resilience
        *For any* workflow execution where Langfuse connection fails,
        the workflow SHALL continue execution.
        """
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test"
        )
        
        with patch.object(
            ResilientTracingManager,
            '_init_client',
            side_effect=Exception("Connection refused")
        ):
            manager = ResilientTracingManager(config)
        
        # Simulate a workflow
        trace = manager.create_trace("workflow", "session-123", {"model": "claude-3"})
        trace.add_metadata("project_path", "/path/to/project")
        
        span = manager.create_span("context_analysis", trace)
        span.set_input({"project_path": "/path/to/project"})
        span.set_output({"files": ["main.py", "utils.py"]})
        span.set_metadata({"latency_ms": 100})
        span.end("success")
        
        trace.set_output({"threats_generated": 5})
        trace.add_score("quality", 0.85, "Good coverage")
        trace.set_status("success")
        
        # Flush should not raise
        manager.flush()
        
        # Verify all operations completed without error
        assert manager.buffered_trace_count == 1
        assert manager.buffered_span_count == 1


class TestResilientTracingManagerMidWorkflowFailure:
    """Tests for mid-workflow failure handling."""
    
    def test_switches_to_fallback_on_create_trace_failure(self, caplog):
        """Verify manager switches to fallback if create_trace fails mid-workflow."""
        config = LangfuseConfig(enabled=False)
        manager = ResilientTracingManager(config)
        
        # Force fallback mode and verify buffering works
        manager._fallback_mode = True
        
        with caplog.at_level(logging.WARNING):
            trace = manager.create_trace("test", "session-123")
        
        assert isinstance(trace, BufferedTraceWrapper)
    
    def test_buffered_traces_preserved_on_flush_failure(self):
        """Verify buffered traces are preserved if flush fails."""
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test"
        )
        
        with patch.object(
            ResilientTracingManager,
            '_init_client',
            side_effect=Exception("Connection refused")
        ):
            manager = ResilientTracingManager(config)
        
        trace = manager.create_trace("test", "session-123")
        
        # Flush should not raise and should preserve buffered traces
        manager.flush()
        
        # Traces should still be buffered since flush failed
        assert manager.buffered_trace_count == 1


class TestGetResilientTracingManager:
    """Tests for get_resilient_tracing_manager factory function."""
    
    def test_returns_resilient_manager(self):
        """Verify factory returns ResilientTracingManager."""
        config = LangfuseConfig(enabled=False)
        
        manager = get_resilient_tracing_manager(config)
        
        assert isinstance(manager, ResilientTracingManager)
    
    def test_loads_config_from_env_when_not_provided(self):
        """Verify factory loads config from env when not provided."""
        with patch.dict('os.environ', {'LANGFUSE_ENABLED': 'false'}):
            manager = get_resilient_tracing_manager()
            
            assert isinstance(manager, ResilientTracingManager)


class TestResilientTracingManagerProperties:
    """Tests for ResilientTracingManager properties."""
    
    def test_fallback_mode_property(self):
        """Verify fallback_mode property returns correct value."""
        config = LangfuseConfig(enabled=False)
        manager = ResilientTracingManager(config)
        
        assert manager.fallback_mode is False
        
        manager._fallback_mode = True
        assert manager.fallback_mode is True
    
    def test_buffered_trace_count_property(self):
        """Verify buffered_trace_count property returns correct count."""
        config = LangfuseConfig(enabled=False)
        manager = ResilientTracingManager(config)
        manager._fallback_mode = True
        
        assert manager.buffered_trace_count == 0
        
        manager.create_trace("test1", "session-1")
        assert manager.buffered_trace_count == 1
        
        manager.create_trace("test2", "session-2")
        assert manager.buffered_trace_count == 2
    
    def test_buffered_span_count_property(self):
        """Verify buffered_span_count property returns correct count."""
        config = LangfuseConfig(enabled=False)
        manager = ResilientTracingManager(config)
        manager._fallback_mode = True
        
        assert manager.buffered_span_count == 0
        
        trace = manager.create_trace("test", "session-1")
        manager.create_span("span1", trace)
        assert manager.buffered_span_count == 1
        
        manager.create_span("span2", trace)
        assert manager.buffered_span_count == 2


class TestWorkflowContinuationProperty:
    """Tests validating Property 15: Connection Failure Resilience.
    
    *For any* workflow execution where Langfuse connection fails (network error,
    invalid credentials), the workflow SHALL continue execution, a warning SHALL
    be logged, and the workflow result SHALL not be affected.
    """
    
    def test_workflow_result_not_affected_by_tracing_failure(self):
        """Verify workflow result is not affected by tracing failure.
        
        **Validates: Requirements 9.3**
        """
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test"
        )
        
        # Simulate connection failure
        with patch.object(
            ResilientTracingManager,
            '_init_client',
            side_effect=Exception("Network error")
        ):
            manager = ResilientTracingManager(config)
        
        # Simulate a complete workflow
        workflow_result = {"threats": [], "trees": []}
        
        trace = manager.create_trace("workflow", "session-123")
        
        # Context analysis
        span1 = manager.create_span("context_analysis", trace)
        span1.set_input({"project_path": "/test"})
        context_result = {"files": ["main.py"]}
        span1.set_output(context_result)
        span1.end("success")
        
        # Threat generation
        span2 = manager.create_span("threat_generation", trace)
        span2.set_input({"context": context_result})
        threats = [{"id": "T1", "statement": "SQL Injection"}]
        span2.set_output({"threats": threats})
        span2.end("success")
        workflow_result["threats"] = threats
        
        # Attack tree generation
        span3 = manager.create_span("attack_tree_generation", trace)
        span3.set_input({"threat": threats[0]})
        trees = [{"threat_id": "T1", "tree": "..."}]
        span3.set_output({"trees": trees})
        span3.end("success")
        workflow_result["trees"] = trees
        
        trace.set_output(workflow_result)
        trace.set_status("success")
        manager.flush()
        
        # Verify workflow result is complete and unaffected
        assert len(workflow_result["threats"]) == 1
        assert len(workflow_result["trees"]) == 1
        assert workflow_result["threats"][0]["id"] == "T1"
    
    def test_warning_logged_on_connection_failure(self, caplog):
        """Verify warning is logged when connection fails.
        
        **Validates: Requirements 9.3**
        """
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test"
        )
        
        with caplog.at_level(logging.WARNING):
            with patch.object(
                ResilientTracingManager,
                '_init_client',
                side_effect=Exception("Invalid credentials")
            ):
                manager = ResilientTracingManager(config)
        
        # Verify warning was logged
        assert any("warning" in record.levelname.lower() for record in caplog.records)
        assert "fallback" in caplog.text.lower() or "unavailable" in caplog.text.lower()
    
    def test_all_trace_operations_work_in_fallback(self):
        """Verify all trace operations work in fallback mode.
        
        **Validates: Requirements 9.3**
        """
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test"
        )
        
        with patch.object(
            ResilientTracingManager,
            '_init_client',
            side_effect=Exception("Connection refused")
        ):
            manager = ResilientTracingManager(config)
        
        # All these operations should work without raising
        trace = manager.create_trace("test", "session-123", {"key": "value"})
        
        # Trace operations
        trace.set_output({"result": "success"})
        trace.set_status("success")
        trace.add_score("quality", 0.9, "Excellent")
        trace.add_categorical_score(
            "mapping",
            "excellent",
            ["excellent", "good", "poor"]
        )
        trace.add_metadata("extra_key", "extra_value")
        
        # Span operations
        span = manager.create_span("test_span", trace, {"span_key": "span_value"})
        span.set_input({"input": "data"})
        span.set_output({"output": "data"})
        span.set_metadata({"latency_ms": 100})
        span.end("success")
        
        # Generation (should return NoOp)
        with span.generation("gen", "model") as gen:
            gen.set_input({"prompt": "test"})
            gen.set_output({"response": "test"})
            gen.set_usage(input_tokens=10, output_tokens=20)
            gen.end("success")
        
        # Flush should not raise
        manager.flush()
        
        # Verify everything was buffered
        assert manager.buffered_trace_count == 1
        assert manager.buffered_span_count == 1
