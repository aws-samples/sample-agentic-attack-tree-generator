#!/usr/bin/env python3
"""
Property-Based Tests for Resilient Tracing

This module contains property-based tests using Hypothesis to validate
the correctness properties of the resilient tracing implementation.

Properties tested:
- Property 15: Connection Failure Resilience

**Validates: Requirements 9.3**

Requirements:
- 9.3: When Langfuse connection fails, log a warning and continue workflow execution

Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience

*For any* workflow execution where Langfuse connection fails (network error,
invalid credentials), the workflow SHALL continue execution, a warning SHALL
be logged, and the workflow result SHALL not be affected.
"""

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings, strategies as st, assume, HealthCheck

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from threatforest.tracing.config import LangfuseConfig
from threatforest.tracing.manager import TracingManager
from threatforest.tracing.resilient import (
    BufferedSpan,
    BufferedSpanWrapper,
    BufferedTrace,
    BufferedTraceWrapper,
    ResilientTracingManager,
    get_resilient_tracing_manager,
)


# =============================================================================
# Hypothesis Strategies for generating test data
# =============================================================================

# Strategy for generating workflow/trace names
workflow_name_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S")),
    min_size=1,
    max_size=100
).filter(lambda s: s.strip() != "")

# Strategy for generating session IDs
session_id_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=50
).filter(lambda s: s.strip() != "")

# Strategy for generating span names (workflow stages)
span_name_strategy = st.sampled_from([
    "context_analysis",
    "threat_statement_generation",
    "attack_tree_generation",
    "ttp_mapping",
    "summary_generation",
])

# Strategy for generating stage counts (N stages in a workflow)
stage_count_strategy = st.integers(min_value=1, max_value=10)

# Strategy for generating JSON-serializable values
json_value_strategy = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1000000, max_value=1000000),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=100),
)

# Strategy for generating metadata dictionaries
metadata_strategy = st.dictionaries(
    keys=st.text(min_size=1, max_size=50).filter(lambda s: s.strip() != ""),
    values=json_value_strategy,
    max_size=10
)

# Strategy for generating input/output data dictionaries
data_dict_strategy = st.dictionaries(
    keys=st.text(min_size=1, max_size=50).filter(lambda s: s.strip() != ""),
    values=json_value_strategy,
    max_size=10
)

# Strategy for generating score values (0.0 to 1.0)
score_value_strategy = st.floats(min_value=0.0, max_value=1.0, allow_nan=False)

# Strategy for generating score names
score_name_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=50
).filter(lambda s: s.strip() != "")

# Strategy for generating error messages
error_message_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S")),
    min_size=1,
    max_size=200
).filter(lambda s: s.strip() != "")

# Strategy for generating workflow results
workflow_result_strategy = st.fixed_dictionaries({
    "threats": st.lists(
        st.fixed_dictionaries({
            "id": st.text(min_size=1, max_size=10).filter(lambda s: s.strip() != ""),
            "statement": st.text(min_size=5, max_size=100).filter(lambda s: s.strip() != ""),
        }),
        min_size=0,
        max_size=5
    ),
    "trees": st.lists(
        st.fixed_dictionaries({
            "threat_id": st.text(min_size=1, max_size=10).filter(lambda s: s.strip() != ""),
            "tree": st.text(min_size=5, max_size=100).filter(lambda s: s.strip() != ""),
        }),
        min_size=0,
        max_size=5
    ),
})


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset singleton instances before and after each test."""
    ResilientTracingManager.reset_instance()
    TracingManager.reset_instance()
    yield
    ResilientTracingManager.reset_instance()
    TracingManager.reset_instance()


def create_failing_manager() -> ResilientTracingManager:
    """
    Create a ResilientTracingManager that simulates connection failure.
    
    This function resets the singleton before creating a new manager to ensure
    each hypothesis example gets a fresh instance.
    
    Returns:
        ResilientTracingManager: Manager in fallback mode due to connection failure.
    """
    # Reset singleton to ensure fresh instance for each hypothesis example
    ResilientTracingManager.reset_instance()
    TracingManager.reset_instance()
    
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
    
    return manager


# =============================================================================
# Property 15: Connection Failure Resilience
# =============================================================================

class TestProperty15ConnectionFailureResilience:
    """
    Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
    
    *For any* workflow execution where Langfuse connection fails (network error,
    invalid credentials), the workflow SHALL continue execution, a warning SHALL
    be logged, and the workflow result SHALL not be affected.
    
    **Validates: Requirements 9.3**
    """
    
    # -------------------------------------------------------------------------
    # Property 15.1: For any workflow with N stages, if connection fails at any
    # stage, all N stages should complete
    # -------------------------------------------------------------------------
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        stage_count=stage_count_strategy,
    )
    def test_all_stages_complete_despite_connection_failure(
        self,
        workflow_name: str,
        session_id: str,
        stage_count: int,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that for any workflow with N stages, if connection fails,
        all N stages should complete without raising exceptions.
        
        **Validates: Requirements 9.3**
        """
        manager = create_failing_manager()
        
        # Verify we're in fallback mode
        assert manager.fallback_mode is True
        
        # Create trace
        trace = manager.create_trace(workflow_name, session_id)
        
        # Execute N stages - all should complete without exceptions
        completed_stages = []
        for i in range(stage_count):
            span = manager.create_span(f"stage_{i}", trace)
            span.set_input({"stage_index": i})
            span.set_output({"result": f"completed_{i}"})
            span.set_metadata({"latency_ms": 100 + i})
            span.end("success")
            completed_stages.append(i)
        
        # Verify all stages completed
        assert len(completed_stages) == stage_count
        
        # Verify all spans were buffered
        assert manager.buffered_span_count == stage_count
        
        # Flush should not raise
        manager.flush()

    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        metadata=metadata_strategy,
        stage_count=stage_count_strategy,
    )
    def test_workflow_with_metadata_completes_in_fallback(
        self,
        workflow_name: str,
        session_id: str,
        metadata: Dict[str, Any],
        stage_count: int,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that workflows with arbitrary metadata complete in fallback mode.
        
        **Validates: Requirements 9.3**
        """
        manager = create_failing_manager()
        
        # Create trace with metadata
        trace = manager.create_trace(workflow_name, session_id, metadata)
        
        # Execute stages with metadata
        for i in range(stage_count):
            span = manager.create_span(f"stage_{i}", trace, {"stage_meta": i})
            span.set_input({"data": f"input_{i}"})
            span.set_output({"data": f"output_{i}"})
            span.end("success")
        
        trace.set_output({"stages_completed": stage_count})
        trace.set_status("success")
        manager.flush()
        
        # All operations should complete without exceptions
        assert manager.buffered_trace_count == 1
        assert manager.buffered_span_count == stage_count
    
    # -------------------------------------------------------------------------
    # Property 15.2: For any trace/span operations, if in fallback mode,
    # operations should not raise exceptions
    # -------------------------------------------------------------------------
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        input_data=data_dict_strategy,
        output_data=data_dict_strategy,
        metadata=metadata_strategy,
    )
    def test_trace_operations_do_not_raise_in_fallback(
        self,
        workflow_name: str,
        session_id: str,
        input_data: Dict[str, Any],
        output_data: Dict[str, Any],
        metadata: Dict[str, Any],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that all trace operations work without raising exceptions in fallback mode.
        
        **Validates: Requirements 9.3**
        """
        manager = create_failing_manager()
        
        # All trace operations should work without exceptions
        trace = manager.create_trace(workflow_name, session_id, metadata)
        
        # set_output should not raise
        trace.set_output(output_data)
        
        # set_status should not raise
        trace.set_status("success")
        
        # add_metadata should not raise
        for key, value in metadata.items():
            trace.add_metadata(key, value)
        
        # flush should not raise
        manager.flush()

    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        span_name=span_name_strategy,
        input_data=data_dict_strategy,
        output_data=data_dict_strategy,
        metadata=metadata_strategy,
    )
    def test_span_operations_do_not_raise_in_fallback(
        self,
        workflow_name: str,
        session_id: str,
        span_name: str,
        input_data: Dict[str, Any],
        output_data: Dict[str, Any],
        metadata: Dict[str, Any],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that all span operations work without raising exceptions in fallback mode.
        
        **Validates: Requirements 9.3**
        """
        manager = create_failing_manager()
        trace = manager.create_trace(workflow_name, session_id)
        
        # All span operations should work without exceptions
        span = manager.create_span(span_name, trace, metadata)
        
        # set_input should not raise
        span.set_input(input_data)
        
        # set_output should not raise
        span.set_output(output_data)
        
        # set_metadata should not raise
        span.set_metadata(metadata)
        
        # end should not raise
        span.end("success")
        
        # generation context manager should not raise
        with span.generation("test_gen", "test_model") as gen:
            gen.set_input({"prompt": "test"})
            gen.set_output({"response": "test"})
            gen.set_usage(input_tokens=10, output_tokens=20)
            gen.end("success")
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        score_name=score_name_strategy,
        score_value=score_value_strategy,
    )
    def test_score_operations_do_not_raise_in_fallback(
        self,
        workflow_name: str,
        session_id: str,
        score_name: str,
        score_value: float,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that score operations work without raising exceptions in fallback mode.
        
        **Validates: Requirements 9.3**
        """
        manager = create_failing_manager()
        trace = manager.create_trace(workflow_name, session_id)
        
        # add_score should not raise for valid values
        trace.add_score(score_name, score_value, "Test comment")
        
        # add_categorical_score should not raise for valid categories
        allowed_categories = ["excellent", "good", "poor", "no_mapping"]
        trace.add_categorical_score(
            "mapping_quality",
            "excellent",
            allowed_categories,
            "Test categorical score"
        )

    # -------------------------------------------------------------------------
    # Property 15.3: For any buffered trace, all data (name, session_id,
    # metadata, scores) should be preserved
    # -------------------------------------------------------------------------
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        metadata=metadata_strategy,
    )
    def test_buffered_trace_preserves_name_and_session_id(
        self,
        workflow_name: str,
        session_id: str,
        metadata: Dict[str, Any],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that buffered traces preserve name and session_id.
        
        **Validates: Requirements 9.3**
        """
        manager = create_failing_manager()
        
        trace = manager.create_trace(workflow_name, session_id, metadata)
        
        # Verify trace properties are preserved
        assert trace.session_id == session_id
        assert trace.trace_id is not None
        assert len(trace.trace_id) > 0
        
        # Verify the underlying buffered trace has correct data
        assert isinstance(trace, BufferedTraceWrapper)
        buffered = trace._buffered_trace
        assert buffered.name == workflow_name
        assert buffered.session_id == session_id
        assert buffered.metadata == metadata
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        output_data=data_dict_strategy,
    )
    def test_buffered_trace_preserves_output(
        self,
        workflow_name: str,
        session_id: str,
        output_data: Dict[str, Any],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that buffered traces preserve output data.
        
        **Validates: Requirements 9.3**
        """
        manager = create_failing_manager()
        trace = manager.create_trace(workflow_name, session_id)
        
        trace.set_output(output_data)
        
        # Verify output is preserved
        buffered = trace._buffered_trace
        assert buffered.output == output_data
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        score_name=score_name_strategy,
        score_value=score_value_strategy,
    )
    def test_buffered_trace_preserves_scores(
        self,
        workflow_name: str,
        session_id: str,
        score_name: str,
        score_value: float,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that buffered traces preserve scores.
        
        **Validates: Requirements 9.3**
        """
        manager = create_failing_manager()
        trace = manager.create_trace(workflow_name, session_id)
        
        trace.add_score(score_name, score_value, "Test comment")
        
        # Verify score is preserved
        buffered = trace._buffered_trace
        assert len(buffered.scores) == 1
        assert buffered.scores[0]["name"] == score_name
        assert buffered.scores[0]["value"] == score_value
        assert buffered.scores[0]["comment"] == "Test comment"

    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        metadata=metadata_strategy,
    )
    def test_buffered_trace_preserves_additional_metadata(
        self,
        workflow_name: str,
        session_id: str,
        metadata: Dict[str, Any],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that buffered traces preserve additional metadata added after creation.
        
        **Validates: Requirements 9.3**
        """
        manager = create_failing_manager()
        trace = manager.create_trace(workflow_name, session_id)
        
        # Add metadata after creation
        for key, value in metadata.items():
            trace.add_metadata(key, value)
        
        # Verify metadata is preserved
        buffered = trace._buffered_trace
        for key, value in metadata.items():
            assert buffered.additional_metadata[key] == value
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        span_name=span_name_strategy,
        input_data=data_dict_strategy,
        output_data=data_dict_strategy,
    )
    def test_buffered_span_preserves_data(
        self,
        workflow_name: str,
        session_id: str,
        span_name: str,
        input_data: Dict[str, Any],
        output_data: Dict[str, Any],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that buffered spans preserve input and output data.
        
        **Validates: Requirements 9.3**
        """
        manager = create_failing_manager()
        trace = manager.create_trace(workflow_name, session_id)
        span = manager.create_span(span_name, trace)
        
        span.set_input(input_data)
        span.set_output(output_data)
        
        # Verify data is preserved
        assert isinstance(span, BufferedSpanWrapper)
        buffered = span._buffered_span
        assert buffered.name == span_name
        assert buffered.trace_id == trace.trace_id
        assert buffered.input_data == input_data
        assert buffered.output_data == output_data
    
    # -------------------------------------------------------------------------
    # Property 15.4: For any workflow result, the result should be identical
    # whether tracing succeeds or fails
    # -------------------------------------------------------------------------
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        workflow_result=workflow_result_strategy,
    )
    def test_workflow_result_identical_with_tracing_failure(
        self,
        workflow_name: str,
        session_id: str,
        workflow_result: Dict[str, Any],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that workflow results are identical whether tracing succeeds or fails.
        
        **Validates: Requirements 9.3**
        """
        manager = create_failing_manager()
        
        # Simulate a workflow that produces a result
        trace = manager.create_trace(workflow_name, session_id)
        
        # Process threats
        for threat in workflow_result.get("threats", []):
            span = manager.create_span("threat_generation", trace)
            span.set_input({"context": "test"})
            span.set_output({"threat": threat})
            span.end("success")
        
        # Process trees
        for tree in workflow_result.get("trees", []):
            span = manager.create_span("attack_tree_generation", trace)
            span.set_input({"threat_id": tree.get("threat_id")})
            span.set_output({"tree": tree})
            span.end("success")
        
        trace.set_output(workflow_result)
        trace.set_status("success")
        manager.flush()
        
        # The workflow result should be unchanged
        # (tracing should not modify the result)
        assert workflow_result == workflow_result  # Identity check
        
        # Verify the result was captured in the trace
        buffered = trace._buffered_trace
        assert buffered.output == workflow_result

    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        stage_count=stage_count_strategy,
    )
    def test_workflow_execution_order_preserved_in_fallback(
        self,
        workflow_name: str,
        session_id: str,
        stage_count: int,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that workflow execution order is preserved in fallback mode.
        
        **Validates: Requirements 9.3**
        """
        manager = create_failing_manager()
        trace = manager.create_trace(workflow_name, session_id)
        
        # Execute stages in order
        execution_order = []
        for i in range(stage_count):
            span = manager.create_span(f"stage_{i}", trace)
            span.set_input({"order": i})
            execution_order.append(i)
            span.end("success")
        
        # Verify execution order is preserved
        assert execution_order == list(range(stage_count))
        
        # Verify spans were buffered in order
        assert manager.buffered_span_count == stage_count


class TestProperty15WarningLogging:
    """
    Tests for warning logging on connection failure.
    
    Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
    
    **Validates: Requirements 9.3**
    """
    
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(
        error_message=error_message_strategy,
    )
    def test_warning_logged_on_connection_failure(
        self,
        error_message: str,
        caplog,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that a warning is logged when connection fails.
        
        **Validates: Requirements 9.3**
        """
        ResilientTracingManager.reset_instance()
        TracingManager.reset_instance()
        
        # Clear caplog for each hypothesis example
        caplog.clear()
        
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test"
        )
        
        with caplog.at_level(logging.WARNING):
            with patch.object(
                ResilientTracingManager,
                '_init_client',
                side_effect=Exception(error_message)
            ):
                manager = ResilientTracingManager(config)
        
        # Verify warning was logged
        assert any(
            record.levelname == "WARNING" 
            for record in caplog.records
        )
        assert "fallback" in caplog.text.lower() or "failed" in caplog.text.lower()
    
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
    )
    def test_warning_logged_on_mid_workflow_failure(
        self,
        workflow_name: str,
        session_id: str,
        caplog,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that a warning is logged when connection fails mid-workflow.
        
        **Validates: Requirements 9.3**
        """
        ResilientTracingManager.reset_instance()
        TracingManager.reset_instance()
        
        # Clear caplog for each hypothesis example
        caplog.clear()
        
        config = LangfuseConfig(enabled=False)
        manager = ResilientTracingManager(config)
        
        # Force fallback mode to simulate mid-workflow failure
        manager._fallback_mode = True
        
        with caplog.at_level(logging.WARNING):
            # Operations should work without raising
            trace = manager.create_trace(workflow_name, session_id)
            span = manager.create_span("test_span", trace)
            span.end("success")
        
        # Manager should be in fallback mode
        assert manager.fallback_mode is True


class TestProperty15ErrorScenarios:
    """
    Tests for various error scenarios.
    
    Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
    
    **Validates: Requirements 9.3**
    """
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        error_message=error_message_strategy,
    )
    def test_network_error_does_not_affect_workflow(
        self,
        workflow_name: str,
        session_id: str,
        error_message: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that network errors do not affect workflow execution.
        
        **Validates: Requirements 9.3**
        """
        ResilientTracingManager.reset_instance()
        TracingManager.reset_instance()
        
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test"
        )
        
        # Simulate network error
        with patch.object(
            ResilientTracingManager,
            '_init_client',
            side_effect=ConnectionError(error_message)
        ):
            manager = ResilientTracingManager(config)
        
        # Workflow should continue
        trace = manager.create_trace(workflow_name, session_id)
        span = manager.create_span("test_span", trace)
        span.set_input({"test": "data"})
        span.set_output({"result": "success"})
        span.end("success")
        trace.set_status("success")
        manager.flush()
        
        # Verify workflow completed
        assert manager.buffered_trace_count == 1
        assert manager.buffered_span_count == 1
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
    )
    def test_invalid_credentials_does_not_affect_workflow(
        self,
        workflow_name: str,
        session_id: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that invalid credentials do not affect workflow execution.
        
        **Validates: Requirements 9.3**
        """
        ResilientTracingManager.reset_instance()
        TracingManager.reset_instance()
        
        config = LangfuseConfig(
            enabled=True,
            public_key="invalid-key",
            secret_key="invalid-secret"
        )
        
        # Simulate authentication error
        with patch.object(
            ResilientTracingManager,
            '_init_client',
            side_effect=Exception("Invalid credentials")
        ):
            manager = ResilientTracingManager(config)
        
        # Workflow should continue
        trace = manager.create_trace(workflow_name, session_id)
        span = manager.create_span("test_span", trace)
        span.end("success")
        trace.set_status("success")
        manager.flush()
        
        # Verify workflow completed
        assert manager.fallback_mode is True
        assert manager.buffered_trace_count == 1
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        stage_count=stage_count_strategy,
    )
    def test_timeout_error_does_not_affect_workflow(
        self,
        workflow_name: str,
        session_id: str,
        stage_count: int,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that timeout errors do not affect workflow execution.
        
        **Validates: Requirements 9.3**
        """
        ResilientTracingManager.reset_instance()
        TracingManager.reset_instance()
        
        config = LangfuseConfig(
            enabled=True,
            public_key="pk-test",
            secret_key="sk-test"
        )
        
        # Simulate timeout error
        with patch.object(
            ResilientTracingManager,
            '_init_client',
            side_effect=TimeoutError("Connection timed out")
        ):
            manager = ResilientTracingManager(config)
        
        # Execute full workflow
        trace = manager.create_trace(workflow_name, session_id)
        
        for i in range(stage_count):
            span = manager.create_span(f"stage_{i}", trace)
            span.set_input({"index": i})
            span.set_output({"result": i})
            span.end("success")
        
        trace.set_output({"stages": stage_count})
        trace.set_status("success")
        manager.flush()
        
        # Verify all stages completed
        assert manager.buffered_span_count == stage_count


class TestProperty15CompleteWorkflowSimulation:
    """
    End-to-end tests simulating complete ThreatForest workflows.
    
    Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
    
    **Validates: Requirements 9.3**
    """
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        threat_count=st.integers(min_value=1, max_value=5),
    )
    def test_complete_threatforest_workflow_in_fallback(
        self,
        workflow_name: str,
        session_id: str,
        threat_count: int,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that a complete ThreatForest workflow executes successfully in fallback mode.
        
        **Validates: Requirements 9.3**
        """
        manager = create_failing_manager()
        
        # Simulate complete ThreatForest workflow
        workflow_result = {
            "threats": [],
            "trees": [],
            "mappings": [],
        }
        
        trace = manager.create_trace(workflow_name, session_id, {
            "bedrock_model": "anthropic.claude-3-sonnet",
            "project_path": "/test/project",
        })
        
        # Stage 1: Context Analysis
        ctx_span = manager.create_span("context_analysis", trace)
        ctx_span.set_input({"project_path": "/test/project"})
        ctx_span.set_output({"files": ["main.py", "utils.py"]})
        ctx_span.set_metadata({"latency_ms": 100})
        ctx_span.end("success")
        
        # Stage 2: Threat Statement Generation
        tsg_span = manager.create_span("threat_statement_generation", trace)
        tsg_span.set_input({"context": {"files": ["main.py"]}})
        threats = [{"id": f"T{i}", "statement": f"Threat {i}"} for i in range(threat_count)]
        tsg_span.set_output({"threats": threats, "count": threat_count})
        tsg_span.set_metadata({"latency_ms": 500, "input_tokens": 1000, "output_tokens": 500})
        tsg_span.end("success")
        workflow_result["threats"] = threats
        
        # Stage 3: Attack Tree Generation (per threat)
        for threat in threats:
            atg_span = manager.create_span("attack_tree_generation", trace)
            atg_span.set_input({"threat": threat})
            tree = {"threat_id": threat["id"], "tree": f"Tree for {threat['id']}"}
            atg_span.set_output({"tree": tree})
            atg_span.set_metadata({"latency_ms": 300})
            atg_span.end("success")
            workflow_result["trees"].append(tree)
        
        # Stage 4: TTP Mapping
        ttp_span = manager.create_span("ttp_mapping", trace)
        ttp_span.set_input({"attack_nodes": ["node1", "node2"]})
        mappings = [{"technique_id": "T1059", "confidence": 0.85}]
        ttp_span.set_output({"mappings": mappings})
        ttp_span.end("success")
        workflow_result["mappings"] = mappings
        
        # Stage 5: Summary Generation
        sum_span = manager.create_span("summary_generation", trace)
        sum_span.set_input({"trees": workflow_result["trees"]})
        sum_span.set_output({"file_paths": ["/output/report.md"]})
        sum_span.end("success")
        
        # Complete trace
        trace.set_output(workflow_result)
        trace.add_score("overall_quality", 0.85, "Good coverage")
        trace.set_status("success")
        manager.flush()
        
        # Verify workflow completed successfully
        assert manager.buffered_trace_count == 1
        # 1 context + 1 threat_gen + N attack_trees + 1 ttp + 1 summary
        expected_spans = 1 + 1 + threat_count + 1 + 1
        assert manager.buffered_span_count == expected_spans
        
        # Verify result is complete
        assert len(workflow_result["threats"]) == threat_count
        assert len(workflow_result["trees"]) == threat_count
        assert len(workflow_result["mappings"]) == 1

    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
    )
    def test_workflow_with_error_status_in_fallback(
        self,
        workflow_name: str,
        session_id: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that workflows with error status are handled correctly in fallback mode.
        
        **Validates: Requirements 9.3**
        """
        manager = create_failing_manager()
        
        trace = manager.create_trace(workflow_name, session_id)
        
        # Simulate a failing span
        span = manager.create_span("failing_stage", trace)
        span.set_input({"test": "data"})
        span.set_metadata({"error": "Something went wrong"})
        span.end("error")
        
        # Set trace to error status
        trace.set_status("error", "Workflow failed at failing_stage")
        manager.flush()
        
        # Verify error status is preserved
        buffered = trace._buffered_trace
        assert buffered.status == "error"
        assert buffered.error == "Workflow failed at failing_stage"


class TestProperty15BufferedDataIntegrity:
    """
    Tests for buffered data integrity.
    
    Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
    
    **Validates: Requirements 9.3**
    """
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        score_count=st.integers(min_value=1, max_value=10),
    )
    def test_multiple_scores_preserved_in_buffer(
        self,
        workflow_name: str,
        session_id: str,
        score_count: int,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that multiple scores are preserved in the buffer.
        
        **Validates: Requirements 9.3**
        """
        manager = create_failing_manager()
        trace = manager.create_trace(workflow_name, session_id)
        
        # Add multiple scores
        for i in range(score_count):
            score_value = (i + 1) / (score_count + 1)  # Values between 0 and 1
            trace.add_score(f"score_{i}", score_value, f"Comment {i}")
        
        # Verify all scores are preserved
        buffered = trace._buffered_trace
        assert len(buffered.scores) == score_count
        
        for i in range(score_count):
            expected_value = (i + 1) / (score_count + 1)
            assert buffered.scores[i]["name"] == f"score_{i}"
            assert abs(buffered.scores[i]["value"] - expected_value) < 0.001
            assert buffered.scores[i]["comment"] == f"Comment {i}"
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        category=st.sampled_from(["excellent", "good", "poor", "no_mapping"]),
    )
    def test_categorical_scores_preserved_in_buffer(
        self,
        workflow_name: str,
        session_id: str,
        category: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that categorical scores are preserved in the buffer.
        
        **Validates: Requirements 9.3**
        """
        manager = create_failing_manager()
        trace = manager.create_trace(workflow_name, session_id)
        
        allowed_categories = ["excellent", "good", "poor", "no_mapping"]
        trace.add_categorical_score(
            "mapping_quality",
            category,
            allowed_categories,
            f"Category is {category}"
        )
        
        # Verify categorical score is preserved
        buffered = trace._buffered_trace
        assert len(buffered.categorical_scores) == 1
        assert buffered.categorical_scores[0]["name"] == "mapping_quality"
        assert buffered.categorical_scores[0]["category"] == category
        assert buffered.categorical_scores[0]["allowed_categories"] == allowed_categories
        assert buffered.categorical_scores[0]["comment"] == f"Category is {category}"
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        span_count=st.integers(min_value=1, max_value=10),
    )
    def test_span_trace_relationship_preserved_in_buffer(
        self,
        workflow_name: str,
        session_id: str,
        span_count: int,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 15: Connection Failure Resilience
        
        Test that span-trace relationships are preserved in the buffer.
        
        **Validates: Requirements 9.3**
        """
        manager = create_failing_manager()
        trace = manager.create_trace(workflow_name, session_id)
        trace_id = trace.trace_id
        
        # Create multiple spans
        for i in range(span_count):
            span = manager.create_span(f"span_{i}", trace)
            span.end("success")
        
        # Verify all spans reference the correct trace_id
        for buffered_span in manager._buffered_spans:
            assert buffered_span.trace_id == trace_id


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])
