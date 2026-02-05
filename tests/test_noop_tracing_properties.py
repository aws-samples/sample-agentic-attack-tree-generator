#!/usr/bin/env python3
"""
Property-Based Tests for No-Op Tracing Implementations

This module contains property-based tests using Hypothesis to validate
the correctness properties of the no-op tracing implementations.

Properties tested:
- Property 14: Disabled Tracing is Transparent

**Validates: Requirements 1.2, 9.1, 9.2**

Requirements:
- 1.2: WHEN the enabled flag is false, THE Tracing_Module SHALL skip all Langfuse operations without errors
- 9.1: WHEN Langfuse is not configured, THE Orchestrator SHALL execute workflows without tracing overhead
- 9.2: THE Tracing_Module SHALL use a no-op implementation when disabled to avoid conditional checks
"""

import sys
from pathlib import Path
from typing import Any, Dict, Optional

import pytest
from hypothesis import given, settings, strategies as st, assume

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from threatforest.tracing.config import LangfuseConfig
from threatforest.tracing.interfaces import IGeneration, ISpan, ITrace, ITracingManager
from threatforest.tracing.noop import (
    NoOpGeneration,
    NoOpSpan,
    NoOpTrace,
    NoOpTracingManager,
)


# =============================================================================
# Hypothesis Strategies for generating test data
# =============================================================================

# Strategy for generating workflow/trace names
workflow_name_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S")),
    min_size=0,
    max_size=200
)

# Strategy for generating session IDs
session_id_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S")),
    min_size=0,
    max_size=100
)

# Strategy for generating span names
span_name_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S")),
    min_size=0,
    max_size=100
)

# Strategy for generating model names
model_name_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S")),
    min_size=0,
    max_size=100
)

# Strategy for generating metadata dictionaries
# Using JSON-serializable values
json_value_strategy = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1000000, max_value=1000000),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=100),
)

metadata_strategy = st.dictionaries(
    keys=st.text(min_size=1, max_size=50).filter(lambda s: s.strip() != ""),
    values=json_value_strategy,
    max_size=20
)

# Strategy for generating input/output data dictionaries
data_dict_strategy = st.dictionaries(
    keys=st.text(min_size=1, max_size=50).filter(lambda s: s.strip() != ""),
    values=json_value_strategy,
    max_size=20
)

# Strategy for generating status strings
status_strategy = st.sampled_from(["success", "error", "pending", "running", "completed"])

# Strategy for generating error messages
error_message_strategy = st.one_of(
    st.none(),
    st.text(max_size=500)
)

# Strategy for generating score names
score_name_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=50
).filter(lambda s: s.strip() != "")

# Strategy for generating score values (0.0 to 1.0)
score_value_strategy = st.floats(min_value=0.0, max_value=1.0, allow_nan=False)

# Strategy for generating score comments
score_comment_strategy = st.one_of(
    st.none(),
    st.text(max_size=200)
)

# Strategy for generating token counts
token_count_strategy = st.one_of(
    st.none(),
    st.integers(min_value=0, max_value=100000)
)


# =============================================================================
# Property 14: Disabled Tracing is Transparent
# =============================================================================

class TestProperty14DisabledTracingTransparent:
    """
    Feature: langfuse-evaluation-integration, Property 14: Disabled Tracing is Transparent
    
    *For any* workflow execution where Langfuse is disabled (`enabled=false`),
    the workflow SHALL complete successfully, no exceptions SHALL be raised
    from tracing operations, and no external Langfuse API calls SHALL be made.
    
    **Validates: Requirements 1.2, 9.1, 9.2**
    """
    
    # -------------------------------------------------------------------------
    # NoOpTracingManager Tests
    # -------------------------------------------------------------------------
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        metadata=metadata_strategy
    )
    def test_noop_manager_create_trace_returns_noop_trace(
        self,
        workflow_name: str,
        session_id: str,
        metadata: Dict[str, Any]
    ):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpTracingManager.create_trace() returns a NoOpTrace instance
        for any valid input without raising exceptions.
        """
        manager = NoOpTracingManager()
        
        # Should not raise any exceptions
        trace = manager.create_trace(workflow_name, session_id, metadata)
        
        # Verify no-op behavior
        assert isinstance(trace, NoOpTrace)
        assert isinstance(trace, ITrace)
    
    @settings(max_examples=100)
    @given(
        span_name=span_name_strategy,
        metadata=metadata_strategy
    )
    def test_noop_manager_create_span_returns_noop_span(
        self,
        span_name: str,
        metadata: Dict[str, Any]
    ):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpTracingManager.create_span() returns a NoOpSpan instance
        for any valid input without raising exceptions.
        """
        manager = NoOpTracingManager()
        trace = NoOpTrace()
        
        # Should not raise any exceptions
        span = manager.create_span(span_name, trace, metadata)
        
        # Verify no-op behavior
        assert isinstance(span, NoOpSpan)
        assert isinstance(span, ISpan)
    
    @settings(max_examples=100)
    @given(st.integers(min_value=1, max_value=100))
    def test_noop_manager_flush_does_not_raise(self, call_count: int):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpTracingManager.flush() can be called multiple times
        without raising exceptions.
        """
        manager = NoOpTracingManager()
        
        # Should not raise any exceptions even when called multiple times
        for _ in range(call_count):
            manager.flush()
    
    def test_noop_manager_enabled_returns_false(self):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpTracingManager.enabled property always returns False.
        """
        manager = NoOpTracingManager()
        
        assert manager.enabled is False
    
    # -------------------------------------------------------------------------
    # NoOpTrace Tests
    # -------------------------------------------------------------------------
    
    def test_noop_trace_trace_id_returns_noop(self):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpTrace.trace_id returns "noop".
        """
        trace = NoOpTrace()
        
        assert trace.trace_id == "noop"
    
    def test_noop_trace_session_id_returns_noop(self):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpTrace.session_id returns "noop".
        """
        trace = NoOpTrace()
        
        assert trace.session_id == "noop"
    
    @settings(max_examples=100)
    @given(output=data_dict_strategy)
    def test_noop_trace_set_output_does_not_raise(self, output: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpTrace.set_output() can be called with any valid output
        without raising exceptions.
        """
        trace = NoOpTrace()
        
        # Should not raise any exceptions
        trace.set_output(output)
    
    @settings(max_examples=100)
    @given(
        status=status_strategy,
        error=error_message_strategy
    )
    def test_noop_trace_set_status_does_not_raise(
        self,
        status: str,
        error: Optional[str]
    ):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpTrace.set_status() can be called with any valid status
        and error message without raising exceptions.
        """
        trace = NoOpTrace()
        
        # Should not raise any exceptions
        trace.set_status(status, error)
    
    @settings(max_examples=100)
    @given(
        name=score_name_strategy,
        value=score_value_strategy,
        comment=score_comment_strategy
    )
    def test_noop_trace_add_score_does_not_raise(
        self,
        name: str,
        value: float,
        comment: Optional[str]
    ):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpTrace.add_score() can be called with any valid score
        without raising exceptions.
        """
        trace = NoOpTrace()
        
        # Should not raise any exceptions
        trace.add_score(name, value, comment)
    
    @settings(max_examples=100)
    @given(
        key=st.text(min_size=1, max_size=50).filter(lambda s: s.strip() != ""),
        value=json_value_strategy
    )
    def test_noop_trace_add_metadata_does_not_raise(
        self,
        key: str,
        value: Any
    ):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpTrace.add_metadata() can be called with any valid key-value
        without raising exceptions.
        """
        trace = NoOpTrace()
        
        # Should not raise any exceptions
        trace.add_metadata(key, value)
    
    # -------------------------------------------------------------------------
    # NoOpSpan Tests
    # -------------------------------------------------------------------------
    
    def test_noop_span_span_id_returns_noop(self):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpSpan.span_id returns "noop".
        """
        span = NoOpSpan()
        
        assert span.span_id == "noop"
    
    @settings(max_examples=100)
    @given(input_data=data_dict_strategy)
    def test_noop_span_set_input_does_not_raise(self, input_data: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpSpan.set_input() can be called with any valid input
        without raising exceptions.
        """
        span = NoOpSpan()
        
        # Should not raise any exceptions
        span.set_input(input_data)
    
    @settings(max_examples=100)
    @given(output_data=data_dict_strategy)
    def test_noop_span_set_output_does_not_raise(self, output_data: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpSpan.set_output() can be called with any valid output
        without raising exceptions.
        """
        span = NoOpSpan()
        
        # Should not raise any exceptions
        span.set_output(output_data)
    
    @settings(max_examples=100)
    @given(metadata=metadata_strategy)
    def test_noop_span_set_metadata_does_not_raise(self, metadata: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpSpan.set_metadata() can be called with any valid metadata
        without raising exceptions.
        """
        span = NoOpSpan()
        
        # Should not raise any exceptions
        span.set_metadata(metadata)
    
    @settings(max_examples=100)
    @given(status=status_strategy)
    def test_noop_span_end_does_not_raise(self, status: str):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpSpan.end() can be called with any valid status
        without raising exceptions.
        """
        span = NoOpSpan()
        
        # Should not raise any exceptions
        span.end(status)
    
    @settings(max_examples=100)
    @given(
        name=span_name_strategy,
        model=model_name_strategy
    )
    def test_noop_span_generation_context_manager_works(
        self,
        name: str,
        model: str
    ):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpSpan.generation() context manager works correctly
        and returns a NoOpGeneration instance.
        """
        span = NoOpSpan()
        
        # Should not raise any exceptions
        with span.generation(name, model) as gen:
            assert isinstance(gen, NoOpGeneration)
            assert isinstance(gen, IGeneration)
    
    # -------------------------------------------------------------------------
    # NoOpGeneration Tests
    # -------------------------------------------------------------------------
    
    def test_noop_generation_generation_id_returns_noop(self):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpGeneration.generation_id returns "noop".
        """
        gen = NoOpGeneration()
        
        assert gen.generation_id == "noop"
    
    @settings(max_examples=100)
    @given(input_data=data_dict_strategy)
    def test_noop_generation_set_input_does_not_raise(self, input_data: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpGeneration.set_input() can be called with any valid input
        without raising exceptions.
        """
        gen = NoOpGeneration()
        
        # Should not raise any exceptions
        gen.set_input(input_data)
    
    @settings(max_examples=100)
    @given(output_data=data_dict_strategy)
    def test_noop_generation_set_output_does_not_raise(self, output_data: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpGeneration.set_output() can be called with any valid output
        without raising exceptions.
        """
        gen = NoOpGeneration()
        
        # Should not raise any exceptions
        gen.set_output(output_data)
    
    @settings(max_examples=100)
    @given(
        input_tokens=token_count_strategy,
        output_tokens=token_count_strategy,
        total_tokens=token_count_strategy
    )
    def test_noop_generation_set_usage_does_not_raise(
        self,
        input_tokens: Optional[int],
        output_tokens: Optional[int],
        total_tokens: Optional[int]
    ):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpGeneration.set_usage() can be called with any valid token counts
        without raising exceptions.
        """
        gen = NoOpGeneration()
        
        # Should not raise any exceptions
        gen.set_usage(input_tokens, output_tokens, total_tokens)
    
    @settings(max_examples=100)
    @given(status=status_strategy)
    def test_noop_generation_end_does_not_raise(self, status: str):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpGeneration.end() can be called with any valid status
        without raising exceptions.
        """
        gen = NoOpGeneration()
        
        # Should not raise any exceptions
        gen.end(status)
    
    # -------------------------------------------------------------------------
    # End-to-End No-Op Workflow Tests
    # -------------------------------------------------------------------------
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        metadata=metadata_strategy
    )
    def test_complete_noop_workflow_does_not_raise(
        self,
        workflow_name: str,
        session_id: str,
        metadata: Dict[str, Any]
    ):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that a complete workflow using NoOp implementations does not raise
        any exceptions. This simulates a full ThreatForest workflow with tracing disabled.
        """
        # Create manager with disabled config
        config = LangfuseConfig(enabled=False)
        manager = NoOpTracingManager()
        
        # Verify manager is disabled
        assert manager.enabled is False
        
        # Create trace
        trace = manager.create_trace(workflow_name, session_id, metadata)
        assert isinstance(trace, NoOpTrace)
        
        # Create span
        span = manager.create_span("test_span", trace)
        assert isinstance(span, NoOpSpan)
        
        # Set span input/output
        span.set_input({"test": "data"})
        span.set_output({"result": "success"})
        span.set_metadata({"latency_ms": 100})
        
        # Use generation context manager
        with span.generation("test_generation", "test_model") as gen:
            gen.set_input({"prompt": "test"})
            gen.set_output({"response": "test"})
            gen.set_usage(input_tokens=10, output_tokens=20, total_tokens=30)
        
        # End span
        span.end("success")
        
        # Set trace output and status
        trace.set_output({"threats": 5})
        trace.add_score("quality", 0.9, "Good quality")
        trace.add_metadata("model", "test_model")
        trace.set_status("success")
        
        # Flush
        manager.flush()
        
        # Verify all IDs are "noop"
        assert trace.trace_id == "noop"
        assert trace.session_id == "noop"
        assert span.span_id == "noop"
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        metadata=metadata_strategy,
        span_count=st.integers(min_value=1, max_value=10)
    )
    def test_multiple_spans_in_noop_workflow(
        self,
        workflow_name: str,
        metadata: Dict[str, Any],
        span_count: int
    ):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that multiple spans can be created in a NoOp workflow without
        raising exceptions.
        """
        manager = NoOpTracingManager()
        trace = manager.create_trace(workflow_name, "session_123", metadata)
        
        spans = []
        for i in range(span_count):
            span = manager.create_span(f"span_{i}", trace)
            span.set_input({"index": i})
            span.set_output({"result": f"result_{i}"})
            span.end("success")
            spans.append(span)
        
        # All spans should be NoOpSpan instances
        for span in spans:
            assert isinstance(span, NoOpSpan)
            assert span.span_id == "noop"
        
        trace.set_status("success")
        manager.flush()
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        error_message=st.text(max_size=200)
    )
    def test_noop_workflow_with_error_status(
        self,
        workflow_name: str,
        error_message: str
    ):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOp implementations handle error status correctly without
        raising exceptions.
        """
        manager = NoOpTracingManager()
        trace = manager.create_trace(workflow_name, "session_123")
        
        span = manager.create_span("failing_span", trace)
        span.set_input({"test": "data"})
        span.set_metadata({"error": error_message})
        span.end("error")
        
        trace.set_status("error", error_message)
        manager.flush()
        
        # Should complete without exceptions
        assert trace.trace_id == "noop"


class TestNoOpInterfaceCompliance:
    """
    Tests to verify that NoOp implementations properly implement their interfaces.
    
    **Validates: Requirements 9.2**
    """
    
    def test_noop_tracing_manager_implements_interface(self):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpTracingManager properly implements ITracingManager interface.
        """
        manager = NoOpTracingManager()
        
        assert isinstance(manager, ITracingManager)
        assert hasattr(manager, 'create_trace')
        assert hasattr(manager, 'create_span')
        assert hasattr(manager, 'flush')
        assert hasattr(manager, 'enabled')
    
    def test_noop_trace_implements_interface(self):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpTrace properly implements ITrace interface.
        """
        trace = NoOpTrace()
        
        assert isinstance(trace, ITrace)
        assert hasattr(trace, 'trace_id')
        assert hasattr(trace, 'session_id')
        assert hasattr(trace, 'set_output')
        assert hasattr(trace, 'set_status')
        assert hasattr(trace, 'add_score')
        assert hasattr(trace, 'add_metadata')
    
    def test_noop_span_implements_interface(self):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpSpan properly implements ISpan interface.
        """
        span = NoOpSpan()
        
        assert isinstance(span, ISpan)
        assert hasattr(span, 'span_id')
        assert hasattr(span, 'set_input')
        assert hasattr(span, 'set_output')
        assert hasattr(span, 'set_metadata')
        assert hasattr(span, 'end')
        assert hasattr(span, 'generation')
    
    def test_noop_generation_implements_interface(self):
        """
        Feature: langfuse-evaluation-integration, Property 14: Disabled tracing is transparent
        
        Test that NoOpGeneration properly implements IGeneration interface.
        """
        gen = NoOpGeneration()
        
        assert isinstance(gen, IGeneration)
        assert hasattr(gen, 'generation_id')
        assert hasattr(gen, 'set_input')
        assert hasattr(gen, 'set_output')
        assert hasattr(gen, 'set_usage')
        assert hasattr(gen, 'end')


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])
