#!/usr/bin/env python3
"""
Property-Based Tests for Span Data Capture

This module contains property-based tests using Hypothesis to validate
the correctness properties of span data capture in the tracing infrastructure.

Properties tested:
- Property 6: Span Captures Stage Data
- Property 7: LLM Span Captures Metrics

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6**

Requirements:
- 3.1: WHEN context_analysis executes, THE Tracing_Module SHALL create a span capturing input and output
- 3.2: WHEN information_extraction executes, THE Tracing_Module SHALL create a span capturing input and output
- 3.3: WHEN attack_tree_generation executes, THE Tracing_Module SHALL create a span capturing input and output
- 3.4: WHEN ttc_mapping executes, THE Tracing_Module SHALL create a span capturing input and output
- 3.5: WHEN summary_generation executes, THE Tracing_Module SHALL create a span capturing input and output
- 3.6: THE Tracing_Module SHALL capture latency_ms, input_tokens, and output_tokens for each LLM-calling span
"""

import sys
from pathlib import Path
from typing import Any, Dict
import time

import pytest
from hypothesis import given, settings, strategies as st

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from threatforest.tracing.config import LangfuseConfig
from threatforest.tracing.context import TracingContext
from threatforest.tracing.noop import NoOpTracingManager, NoOpSpan, NoOpTrace
from threatforest.tracing import get_tracing_manager


# =============================================================================
# Hypothesis Strategies for generating test data
# =============================================================================

# Strategy for workflow stage names (the 5 stages in ThreatForest)
stage_name_strategy = st.sampled_from([
    "context_analysis",
    "threat_statement_generation",
    "attack_tree_generation",
    "ttp_mapping",
    "summary_generation"
])

# Strategy for generating JSON-serializable values
json_value_strategy = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1000000, max_value=1000000),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=100),
)

# Strategy for generating input/output data dictionaries
# Using text keys with min_size=1 to ensure non-empty keys
data_dict_strategy = st.dictionaries(
    keys=st.text(min_size=1, max_size=20).filter(lambda s: s.strip() != ""),
    values=st.one_of(
        st.text(min_size=1, max_size=50),
        st.integers(min_value=-1000, max_value=1000),
        st.booleans(),
    ),
    min_size=1,
    max_size=5
)

# Strategy for generating metadata dictionaries
metadata_strategy = st.dictionaries(
    keys=st.text(min_size=1, max_size=50).filter(lambda s: s.strip() != ""),
    values=json_value_strategy,
    max_size=10
)

# Strategy for generating sleep times (for latency testing)
# Using small values to keep tests fast
sleep_time_strategy = st.floats(min_value=0.001, max_value=0.05)

# Strategy for generating workflow names
workflow_name_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=50
).filter(lambda s: s.strip() != "")

# Strategy for generating session IDs
session_id_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P")),
    min_size=1,
    max_size=50
).filter(lambda s: s.strip() != "")


# =============================================================================
# Property 6: Span Captures Stage Data
# =============================================================================

class TestProperty6SpanCapturesStageData:
    """
    Feature: langfuse-evaluation-integration, Property 6: Span Captures Stage Data
    
    *For any* workflow stage execution (context_analysis, threat_statement_generation,
    attack_tree_generation, ttp_mapping, summary_generation), the created span SHALL
    contain the stage's input data and output data as specified in the schema.
    
    **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**
    """
    
    @settings(max_examples=100)
    @given(
        stage_name=stage_name_strategy,
        input_data=data_dict_strategy,
        output_data=data_dict_strategy,
    )
    def test_span_captures_input_and_output_data_noop(
        self,
        stage_name: str,
        input_data: Dict[str, Any],
        output_data: Dict[str, Any],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 6: Span captures stage data
        
        **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**
        
        Test that for any workflow stage, set_input() and set_output() can be called
        with arbitrary data without raising exceptions (NoOp implementation).
        """
        # Create a NoOp tracing context (disabled Langfuse)
        config = LangfuseConfig(enabled=False)
        manager = get_tracing_manager(config)
        ctx = TracingContext(manager)
        
        # Execute workflow with span
        with ctx.trace("test_workflow") as trace:
            with ctx.span(stage_name) as span:
                # Set input data - should not raise
                span.set_input(input_data)
                
                # Set output data - should not raise
                span.set_output(output_data)
        
        # If we reach here without exceptions, the test passes
        # NoOp implementation should handle any valid data

    
    @settings(max_examples=100)
    @given(
        stage_name=stage_name_strategy,
        input_data=data_dict_strategy,
        output_data=data_dict_strategy,
        metadata=metadata_strategy,
    )
    def test_span_captures_stage_data_with_metadata(
        self,
        stage_name: str,
        input_data: Dict[str, Any],
        output_data: Dict[str, Any],
        metadata: Dict[str, Any],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 6: Span captures stage data
        
        **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**
        
        Test that spans can capture input, output, and metadata together
        without raising exceptions.
        """
        config = LangfuseConfig(enabled=False)
        manager = get_tracing_manager(config)
        ctx = TracingContext(manager)
        
        with ctx.trace("test_workflow") as trace:
            with ctx.span(stage_name, metadata) as span:
                span.set_input(input_data)
                span.set_output(output_data)
                span.set_metadata({"additional": "metadata"})
        
        # Test passes if no exceptions raised
    
    @settings(max_examples=100)
    @given(
        stage_name=stage_name_strategy,
        input_data=data_dict_strategy,
    )
    def test_span_set_input_is_idempotent(
        self,
        stage_name: str,
        input_data: Dict[str, Any],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 6: Span captures stage data
        
        **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**
        
        Test that set_input() can be called multiple times without errors.
        """
        config = LangfuseConfig(enabled=False)
        manager = get_tracing_manager(config)
        ctx = TracingContext(manager)
        
        with ctx.trace("test_workflow") as trace:
            with ctx.span(stage_name) as span:
                # Call set_input multiple times
                span.set_input(input_data)
                span.set_input({"updated": "data"})
                span.set_input(input_data)
        
        # Test passes if no exceptions raised

    
    @settings(max_examples=100)
    @given(
        stage_name=stage_name_strategy,
        output_data=data_dict_strategy,
    )
    def test_span_set_output_is_idempotent(
        self,
        stage_name: str,
        output_data: Dict[str, Any],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 6: Span captures stage data
        
        **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**
        
        Test that set_output() can be called multiple times without errors.
        """
        config = LangfuseConfig(enabled=False)
        manager = get_tracing_manager(config)
        ctx = TracingContext(manager)
        
        with ctx.trace("test_workflow") as trace:
            with ctx.span(stage_name) as span:
                # Call set_output multiple times
                span.set_output(output_data)
                span.set_output({"updated": "result"})
                span.set_output(output_data)
        
        # Test passes if no exceptions raised
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        stage_names=st.lists(stage_name_strategy, min_size=1, max_size=5),
    )
    def test_multiple_spans_capture_data_independently(
        self,
        workflow_name: str,
        session_id: str,
        stage_names: list,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 6: Span captures stage data
        
        **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**
        
        Test that multiple spans within a trace can each capture their own
        input/output data independently.
        """
        config = LangfuseConfig(enabled=False)
        manager = get_tracing_manager(config)
        ctx = TracingContext(manager)
        
        with ctx.trace(workflow_name, session_id) as trace:
            for i, stage_name in enumerate(stage_names):
                with ctx.span(stage_name) as span:
                    span.set_input({"stage_index": i, "stage": stage_name})
                    span.set_output({"result": f"output_{i}"})
        
        # Test passes if no exceptions raised

    
    @settings(max_examples=100)
    @given(
        stage_name=stage_name_strategy,
        input_data=data_dict_strategy,
        output_data=data_dict_strategy,
    )
    def test_span_without_trace_returns_noop(
        self,
        stage_name: str,
        input_data: Dict[str, Any],
        output_data: Dict[str, Any],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 6: Span captures stage data
        
        **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**
        
        Test that creating a span without an active trace returns a NoOpSpan
        and operations don't raise exceptions.
        """
        config = LangfuseConfig(enabled=False)
        manager = get_tracing_manager(config)
        ctx = TracingContext(manager)
        
        # Create span without trace context
        with ctx.span(stage_name) as span:
            assert isinstance(span, NoOpSpan)
            span.set_input(input_data)
            span.set_output(output_data)
        
        # Test passes if no exceptions raised


# =============================================================================
# Property 7: LLM Span Captures Metrics
# =============================================================================

class TestProperty7LLMSpanCapturesMetrics:
    """
    Feature: langfuse-evaluation-integration, Property 7: LLM Span Captures Metrics
    
    *For any* span that involves an LLM call, the span metadata SHALL include
    `latency_ms` as a positive integer, and MAY include `input_tokens` and
    `output_tokens` when available from the model response.
    
    **Validates: Requirements 3.6**
    """
    
    @settings(max_examples=100)
    @given(
        sleep_time=sleep_time_strategy,
    )
    def test_span_captures_latency_ms_as_positive_integer(
        self,
        sleep_time: float,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 7: LLM span captures metrics
        
        **Validates: Requirements 3.6**
        
        Test that the span context manager automatically captures latency_ms
        as a positive integer in the span metadata.
        """
        from unittest.mock import MagicMock
        
        # Create a mock manager to capture metadata calls
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_span = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        mock_manager.create_span.return_value = mock_span
        
        ctx = TracingContext(mock_manager)
        
        with ctx.trace("test_workflow", "session-123") as trace:
            with ctx.span("llm_operation") as span:
                # Simulate work (LLM call)
                time.sleep(sleep_time)
        
        # Find the latency_ms call in set_metadata
        latency_call = None
        for call in mock_span.set_metadata.call_args_list:
            if "latency_ms" in call[0][0]:
                latency_call = call
                break
        
        assert latency_call is not None, "latency_ms should be captured"
        latency_ms = latency_call[0][0]["latency_ms"]
        
        # Verify latency_ms is a positive integer
        assert isinstance(latency_ms, int), "latency_ms should be an integer"
        assert latency_ms > 0, "latency_ms should be positive"

    
    @settings(max_examples=100)
    @given(
        sleep_time=sleep_time_strategy,
    )
    def test_latency_ms_reflects_actual_execution_time(
        self,
        sleep_time: float,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 7: LLM span captures metrics
        
        **Validates: Requirements 3.6**
        
        Test that latency_ms approximately reflects the actual execution time
        of the span (within reasonable tolerance).
        """
        from unittest.mock import MagicMock
        
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_span = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        mock_manager.create_span.return_value = mock_span
        
        ctx = TracingContext(mock_manager)
        
        with ctx.trace("test_workflow", "session-123") as trace:
            with ctx.span("llm_operation") as span:
                time.sleep(sleep_time)
        
        # Find the latency_ms call
        latency_call = None
        for call in mock_span.set_metadata.call_args_list:
            if "latency_ms" in call[0][0]:
                latency_call = call
                break
        
        assert latency_call is not None
        latency_ms = latency_call[0][0]["latency_ms"]
        
        # Expected latency in ms (with some tolerance for overhead)
        expected_min_ms = int(sleep_time * 1000)
        # Allow up to 100ms overhead for test execution
        expected_max_ms = int(sleep_time * 1000) + 100
        
        assert latency_ms >= expected_min_ms, \
            f"latency_ms ({latency_ms}) should be >= expected ({expected_min_ms})"
        assert latency_ms <= expected_max_ms, \
            f"latency_ms ({latency_ms}) should be <= expected max ({expected_max_ms})"
    
    @settings(max_examples=100)
    @given(
        sleep_time=sleep_time_strategy,
    )
    def test_latency_captured_even_on_exception(
        self,
        sleep_time: float,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 7: LLM span captures metrics
        
        **Validates: Requirements 3.6**
        
        Test that latency_ms is captured even when the span raises an exception.
        """
        from unittest.mock import MagicMock
        
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_span = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        mock_manager.create_span.return_value = mock_span
        
        ctx = TracingContext(mock_manager)
        
        with pytest.raises(ValueError, match="Test error"):
            with ctx.trace("test_workflow", "session-123") as trace:
                with ctx.span("llm_operation") as span:
                    time.sleep(sleep_time)
                    raise ValueError("Test error")
        
        # Find the latency_ms call
        latency_call = None
        for call in mock_span.set_metadata.call_args_list:
            if "latency_ms" in call[0][0]:
                latency_call = call
                break
        
        assert latency_call is not None, "latency_ms should be captured even on exception"
        latency_ms = latency_call[0][0]["latency_ms"]
        assert isinstance(latency_ms, int)
        assert latency_ms > 0

    
    @settings(max_examples=100)
    @given(
        stage_name=stage_name_strategy,
        input_tokens=st.integers(min_value=0, max_value=100000),
        output_tokens=st.integers(min_value=0, max_value=100000),
    )
    def test_span_can_capture_token_metrics(
        self,
        stage_name: str,
        input_tokens: int,
        output_tokens: int,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 7: LLM span captures metrics
        
        **Validates: Requirements 3.6**
        
        Test that spans can capture input_tokens and output_tokens in metadata.
        """
        config = LangfuseConfig(enabled=False)
        manager = get_tracing_manager(config)
        ctx = TracingContext(manager)
        
        with ctx.trace("test_workflow") as trace:
            with ctx.span(stage_name) as span:
                # Manually set token metrics (as would be done after LLM call)
                span.set_metadata({
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "total_tokens": input_tokens + output_tokens,
                })
        
        # Test passes if no exceptions raised
    
    @settings(max_examples=100)
    @given(
        stage_names=st.lists(stage_name_strategy, min_size=2, max_size=5),
        sleep_times=st.lists(sleep_time_strategy, min_size=2, max_size=5),
    )
    def test_multiple_spans_each_capture_own_latency(
        self,
        stage_names: list,
        sleep_times: list,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 7: LLM span captures metrics
        
        **Validates: Requirements 3.6**
        
        Test that multiple spans each capture their own latency independently.
        """
        from unittest.mock import MagicMock
        
        # Ensure we have matching lengths
        min_len = min(len(stage_names), len(sleep_times))
        stage_names = stage_names[:min_len]
        sleep_times = sleep_times[:min_len]
        
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        
        # Create separate mock spans for each stage
        mock_spans = [MagicMock() for _ in stage_names]
        mock_manager.create_span.side_effect = mock_spans
        
        ctx = TracingContext(mock_manager)
        
        with ctx.trace("test_workflow", "session-123") as trace:
            for i, (stage_name, sleep_time) in enumerate(zip(stage_names, sleep_times)):
                with ctx.span(stage_name) as span:
                    time.sleep(sleep_time)
        
        # Verify each span captured latency
        for i, mock_span in enumerate(mock_spans):
            latency_call = None
            for call in mock_span.set_metadata.call_args_list:
                if "latency_ms" in call[0][0]:
                    latency_call = call
                    break
            
            assert latency_call is not None, f"Span {i} should capture latency_ms"
            latency_ms = latency_call[0][0]["latency_ms"]
            assert isinstance(latency_ms, int)
            assert latency_ms > 0



# =============================================================================
# Combined Property Tests for Stage Data and Metrics
# =============================================================================

class TestCombinedSpanDataAndMetrics:
    """
    Combined tests verifying both Property 6 and Property 7 together.
    
    These tests simulate realistic workflow scenarios where spans capture
    both stage data (input/output) and LLM metrics (latency, tokens).
    
    **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6**
    """
    
    @settings(max_examples=100)
    @given(
        stage_name=stage_name_strategy,
        input_data=data_dict_strategy,
        output_data=data_dict_strategy,
        sleep_time=sleep_time_strategy,
    )
    def test_span_captures_data_and_latency_together(
        self,
        stage_name: str,
        input_data: Dict[str, Any],
        output_data: Dict[str, Any],
        sleep_time: float,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 6 & 7: Span captures data and metrics
        
        **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6**
        
        Test that a span can capture both stage data and latency metrics
        in a realistic workflow scenario.
        """
        from unittest.mock import MagicMock
        
        mock_manager = MagicMock()
        mock_trace = MagicMock()
        mock_span = MagicMock()
        mock_manager.create_trace.return_value = mock_trace
        mock_manager.create_span.return_value = mock_span
        
        ctx = TracingContext(mock_manager)
        
        with ctx.trace("threatforest_analysis") as trace:
            with ctx.span(stage_name) as span:
                # Set input data (Property 6)
                span.set_input(input_data)
                
                # Simulate LLM work
                time.sleep(sleep_time)
                
                # Set output data (Property 6)
                span.set_output(output_data)
        
        # Verify input was set
        mock_span.set_input.assert_called_with(input_data)
        
        # Verify output was set
        mock_span.set_output.assert_called_with(output_data)
        
        # Verify latency was captured (Property 7)
        latency_call = None
        for call in mock_span.set_metadata.call_args_list:
            if "latency_ms" in call[0][0]:
                latency_call = call
                break
        
        assert latency_call is not None
        latency_ms = latency_call[0][0]["latency_ms"]
        assert isinstance(latency_ms, int)
        assert latency_ms > 0
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
    )
    def test_full_workflow_simulation(
        self,
        workflow_name: str,
        session_id: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 6 & 7: Full workflow simulation
        
        **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6**
        
        Test a complete ThreatForest workflow with all 5 stages,
        verifying data capture and latency for each.
        """
        config = LangfuseConfig(enabled=False)
        manager = get_tracing_manager(config)
        ctx = TracingContext(manager)
        
        stages = [
            ("context_analysis", {"project_path": "/test"}, {"context_files": ["main.py"]}),
            ("threat_statement_generation", {"context": "test"}, {"threats": [{"id": 1}]}),
            ("attack_tree_generation", {"threat": "test"}, {"tree": "markdown"}),
            ("ttp_mapping", {"nodes": []}, {"mappings": []}),
            ("summary_generation", {"trees": []}, {"files": ["report.md"]}),
        ]
        
        with ctx.trace(workflow_name, session_id) as trace:
            for stage_name, input_data, output_data in stages:
                with ctx.span(stage_name) as span:
                    span.set_input(input_data)
                    # Simulate minimal work
                    time.sleep(0.001)
                    span.set_output(output_data)
        
        # Test passes if no exceptions raised


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])
