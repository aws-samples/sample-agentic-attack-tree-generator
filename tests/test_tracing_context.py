"""
Unit Tests for TracingContext

This module contains unit tests for the TracingContext class, verifying:
- trace() context manager creates traces and handles success/error status
- span() context manager creates spans with automatic latency capture
- session_id generation and propagation
- NoOp fallback when no trace is active

Requirements tested:
- 8.1: Generate unique session_id at workflow start
- 8.2: Propagate session_id to all child spans
"""

import pytest
from unittest.mock import MagicMock, patch
import time

from threatforest.tracing import (
    LangfuseConfig,
    TracingContext,
    NoOpTracingManager,
    NoOpTrace,
    NoOpSpan,
    get_tracing_manager,
)


class TestTracingContextTrace:
    """Tests for TracingContext.trace() context manager."""
    
    def test_trace_creates_trace_with_manager(self):
        """Verify trace() creates a trace using the manager."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        
        ctx = TracingContext(mock_manager)
        
        with ctx.trace("test_workflow", "session-123") as trace:
            assert trace is mock_trace
        
        mock_manager.create_trace.assert_called_once_with(
            "test_workflow", "session-123", None
        )
    
    def test_trace_generates_session_id_if_not_provided(self):
        """Verify trace() generates a UUID session_id if not provided."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        
        ctx = TracingContext(mock_manager)
        
        with ctx.trace("test_workflow") as trace:
            pass
        
        # Verify create_trace was called with a generated session_id
        call_args = mock_manager.create_trace.call_args
        session_id = call_args[0][1]  # Second positional argument
        
        # Should be a valid UUID format (36 characters with hyphens)
        assert len(session_id) == 36
        assert session_id.count('-') == 4
    
    def test_trace_passes_metadata_to_manager(self):
        """Verify trace() passes metadata to the manager."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        
        ctx = TracingContext(mock_manager)
        metadata = {"bedrock_model": "claude-3", "project_path": "/test"}
        
        with ctx.trace("test_workflow", "session-123", metadata) as trace:
            pass
        
        mock_manager.create_trace.assert_called_once_with(
            "test_workflow", "session-123", metadata
        )
    
    def test_trace_sets_success_status_on_normal_exit(self):
        """Verify trace() sets success status when context exits normally."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        
        ctx = TracingContext(mock_manager)
        
        with ctx.trace("test_workflow", "session-123") as trace:
            pass
        
        mock_trace.set_status.assert_called_once_with("success")
    
    def test_trace_sets_error_status_on_exception(self):
        """Verify trace() sets error status when exception is raised."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        
        ctx = TracingContext(mock_manager)
        
        with pytest.raises(ValueError, match="Test error"):
            with ctx.trace("test_workflow", "session-123") as trace:
                raise ValueError("Test error")
        
        mock_trace.set_status.assert_called_once_with("error", "Test error")
    
    def test_trace_flushes_manager_on_exit(self):
        """Verify trace() flushes the manager when context exits."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        
        ctx = TracingContext(mock_manager)
        
        with ctx.trace("test_workflow", "session-123") as trace:
            pass
        
        mock_manager.flush.assert_called_once()
    
    def test_trace_flushes_manager_on_exception(self):
        """Verify trace() flushes the manager even when exception is raised."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        
        ctx = TracingContext(mock_manager)
        
        with pytest.raises(ValueError):
            with ctx.trace("test_workflow", "session-123") as trace:
                raise ValueError("Test error")
        
        mock_manager.flush.assert_called_once()
    
    def test_trace_clears_current_trace_on_exit(self):
        """Verify trace() clears current_trace when context exits."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        
        ctx = TracingContext(mock_manager)
        
        with ctx.trace("test_workflow", "session-123") as trace:
            assert ctx.current_trace is mock_trace
        
        assert ctx.current_trace is None
    
    def test_trace_clears_session_id_on_exit(self):
        """Verify trace() clears current_session_id when context exits."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        
        ctx = TracingContext(mock_manager)
        
        with ctx.trace("test_workflow", "session-123") as trace:
            assert ctx.current_session_id == "session-123"
        
        assert ctx.current_session_id is None


class TestTracingContextSpan:
    """Tests for TracingContext.span() context manager."""
    
    def test_span_creates_span_with_manager(self):
        """Verify span() creates a span using the manager."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_span = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        mock_manager.create_span.return_value = mock_span
        
        ctx = TracingContext(mock_manager)
        
        with ctx.trace("test_workflow", "session-123") as trace:
            with ctx.span("test_span") as span:
                assert span is mock_span
        
        mock_manager.create_span.assert_called_once_with(
            "test_span", mock_trace, None
        )
    
    def test_span_returns_noop_when_no_trace(self):
        """Verify span() returns NoOpSpan when no trace is active."""
        mock_manager = MagicMock()
        
        ctx = TracingContext(mock_manager)
        
        with ctx.span("test_span") as span:
            assert isinstance(span, NoOpSpan)
        
        mock_manager.create_span.assert_not_called()
    
    def test_span_passes_metadata_to_manager(self):
        """Verify span() passes metadata to the manager."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_span = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        mock_manager.create_span.return_value = mock_span
        
        ctx = TracingContext(mock_manager)
        metadata = {"stage": "analysis"}
        
        with ctx.trace("test_workflow", "session-123") as trace:
            with ctx.span("test_span", metadata) as span:
                pass
        
        mock_manager.create_span.assert_called_once_with(
            "test_span", mock_trace, metadata
        )
    
    def test_span_ends_with_success_on_normal_exit(self):
        """Verify span() calls end('success') when context exits normally."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_span = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        mock_manager.create_span.return_value = mock_span
        
        ctx = TracingContext(mock_manager)
        
        with ctx.trace("test_workflow", "session-123") as trace:
            with ctx.span("test_span") as span:
                pass
        
        mock_span.end.assert_called_once_with("success")
    
    def test_span_ends_with_error_on_exception(self):
        """Verify span() calls end('error') when exception is raised."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_span = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        mock_manager.create_span.return_value = mock_span
        
        ctx = TracingContext(mock_manager)
        
        with pytest.raises(ValueError, match="Test error"):
            with ctx.trace("test_workflow", "session-123") as trace:
                with ctx.span("test_span") as span:
                    raise ValueError("Test error")
        
        mock_span.end.assert_called_once_with("error")
    
    def test_span_captures_error_in_metadata(self):
        """Verify span() captures error message in metadata on exception."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_span = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        mock_manager.create_span.return_value = mock_span
        
        ctx = TracingContext(mock_manager)
        
        with pytest.raises(ValueError):
            with ctx.trace("test_workflow", "session-123") as trace:
                with ctx.span("test_span") as span:
                    raise ValueError("Test error")
        
        # Check that set_metadata was called with error
        error_call = None
        for call in mock_span.set_metadata.call_args_list:
            if "error" in call[0][0]:
                error_call = call
                break
        
        assert error_call is not None
        assert error_call[0][0]["error"] == "Test error"
    
    def test_span_captures_latency_ms(self):
        """Verify span() captures latency_ms in metadata."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_span = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        mock_manager.create_span.return_value = mock_span
        
        ctx = TracingContext(mock_manager)
        
        with ctx.trace("test_workflow", "session-123") as trace:
            with ctx.span("test_span") as span:
                time.sleep(0.01)  # Sleep 10ms
        
        # Check that set_metadata was called with latency_ms
        latency_call = None
        for call in mock_span.set_metadata.call_args_list:
            if "latency_ms" in call[0][0]:
                latency_call = call
                break
        
        assert latency_call is not None
        latency_ms = latency_call[0][0]["latency_ms"]
        assert isinstance(latency_ms, int)
        assert latency_ms >= 10  # At least 10ms
    
    def test_span_captures_latency_even_on_exception(self):
        """Verify span() captures latency_ms even when exception is raised."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_span = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        mock_manager.create_span.return_value = mock_span
        
        ctx = TracingContext(mock_manager)
        
        with pytest.raises(ValueError):
            with ctx.trace("test_workflow", "session-123") as trace:
                with ctx.span("test_span") as span:
                    time.sleep(0.01)
                    raise ValueError("Test error")
        
        # Check that set_metadata was called with latency_ms
        latency_call = None
        for call in mock_span.set_metadata.call_args_list:
            if "latency_ms" in call[0][0]:
                latency_call = call
                break
        
        assert latency_call is not None


class TestTracingContextSessionPropagation:
    """Tests for session_id propagation in TracingContext."""
    
    def test_session_id_stored_during_trace(self):
        """Verify session_id is stored during trace context."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        
        ctx = TracingContext(mock_manager)
        
        with ctx.trace("test_workflow", "session-123") as trace:
            assert ctx.current_session_id == "session-123"
    
    def test_generated_session_id_stored(self):
        """Verify generated session_id is stored during trace context."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        
        ctx = TracingContext(mock_manager)
        
        with ctx.trace("test_workflow") as trace:
            # Should have a generated session_id
            assert ctx.current_session_id is not None
            assert len(ctx.current_session_id) == 36  # UUID format
    
    def test_span_uses_current_trace_for_session_propagation(self):
        """Verify span() uses current trace which contains session_id."""
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_span = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        mock_manager.create_span.return_value = mock_span
        
        ctx = TracingContext(mock_manager)
        
        with ctx.trace("test_workflow", "session-123") as trace:
            with ctx.span("test_span") as span:
                pass
        
        # Verify span was created with the current trace
        mock_manager.create_span.assert_called_once_with(
            "test_span", mock_trace, None
        )


class TestTracingContextWithNoOpManager:
    """Tests for TracingContext with NoOpTracingManager."""
    
    def test_trace_works_with_noop_manager(self):
        """Verify trace() works correctly with NoOpTracingManager."""
        manager = NoOpTracingManager()
        ctx = TracingContext(manager)
        
        with ctx.trace("test_workflow", "session-123") as trace:
            assert isinstance(trace, NoOpTrace)
    
    def test_span_works_with_noop_manager(self):
        """Verify span() works correctly with NoOpTracingManager."""
        manager = NoOpTracingManager()
        ctx = TracingContext(manager)
        
        with ctx.trace("test_workflow", "session-123") as trace:
            with ctx.span("test_span") as span:
                assert isinstance(span, NoOpSpan)
    
    def test_nested_spans_work_with_noop_manager(self):
        """Verify nested spans work correctly with NoOpTracingManager."""
        manager = NoOpTracingManager()
        ctx = TracingContext(manager)
        
        with ctx.trace("test_workflow", "session-123") as trace:
            with ctx.span("outer_span") as outer:
                with ctx.span("inner_span") as inner:
                    assert isinstance(inner, NoOpSpan)
    
    def test_exception_handling_with_noop_manager(self):
        """Verify exception handling works with NoOpTracingManager."""
        manager = NoOpTracingManager()
        ctx = TracingContext(manager)
        
        with pytest.raises(ValueError, match="Test error"):
            with ctx.trace("test_workflow", "session-123") as trace:
                with ctx.span("test_span") as span:
                    raise ValueError("Test error")


class TestTracingContextIntegration:
    """Integration tests for TracingContext with get_tracing_manager."""
    
    def test_full_workflow_with_disabled_tracing(self):
        """Verify full workflow works with disabled tracing."""
        config = LangfuseConfig(enabled=False)
        manager = get_tracing_manager(config)
        ctx = TracingContext(manager)
        
        results = []
        
        with ctx.trace("threatforest_analysis") as trace:
            trace.add_metadata("bedrock_model", "claude-3")
            
            with ctx.span("context_analysis") as span:
                span.set_input({"project_path": "/test"})
                results.append("context")
                span.set_output({"files": ["main.py"]})
            
            with ctx.span("threat_generation") as span:
                span.set_input({"context": results})
                results.append("threats")
                span.set_output({"threats": 5})
            
            trace.set_output({"total_threats": 5})
        
        assert results == ["context", "threats"]
    
    def test_multiple_sequential_traces(self):
        """Verify multiple sequential traces work correctly."""
        config = LangfuseConfig(enabled=False)
        manager = get_tracing_manager(config)
        ctx = TracingContext(manager)
        
        # First trace
        with ctx.trace("workflow_1", "session-1") as trace1:
            assert ctx.current_session_id == "session-1"
        
        assert ctx.current_trace is None
        assert ctx.current_session_id is None
        
        # Second trace
        with ctx.trace("workflow_2", "session-2") as trace2:
            assert ctx.current_session_id == "session-2"
        
        assert ctx.current_trace is None
        assert ctx.current_session_id is None
