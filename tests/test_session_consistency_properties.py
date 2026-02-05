#!/usr/bin/env python3
"""
Property-Based Tests for Session Consistency

This module contains property-based tests using Hypothesis to validate
the correctness properties of session consistency in the Langfuse tracing module.

Properties tested:
- Property 4: Session Consistency

**Validates: Requirements 2.2, 8.1, 8.2, 8.4**

Requirements:
- 2.2: Attach session_id to group related traces from the same analysis run
- 8.1: Generate unique session_id at workflow start
- 8.2: Propagate session_id to all child spans
- 8.4: Link all tree spans to parent session
"""

import sys
from pathlib import Path
from typing import Any, Dict, List, Set
from unittest.mock import MagicMock, patch, call
import uuid

import pytest
from hypothesis import given, settings, strategies as st, assume

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from threatforest.tracing.config import LangfuseConfig
from threatforest.tracing.manager import (
    TracingManager,
    LangfuseTrace,
    LangfuseSpan,
    get_tracing_manager,
)
from threatforest.tracing.context import TracingContext
from threatforest.tracing.noop import NoOpTrace, NoOpSpan, NoOpTracingManager


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

# Strategy for generating threat counts (N threats generating attack trees)
threat_count_strategy = st.integers(min_value=1, max_value=20)

# Strategy for generating span names
span_name_strategy = st.sampled_from([
    "context_analysis",
    "threat_statement_generation",
    "attack_tree_generation",
    "ttp_mapping",
    "summary_generation",
])

# Strategy for generating threat statement data
threat_statement_strategy = st.fixed_dictionaries({
    "id": st.uuids().map(str),
    "title": st.text(min_size=5, max_size=100).filter(lambda s: s.strip() != ""),
    "description": st.text(min_size=10, max_size=500).filter(lambda s: s.strip() != ""),
})

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


# =============================================================================
# Helper function to create a TracingManager with mocked Langfuse
# =============================================================================

def create_mocked_tracing_manager():
    """
    Create a TracingManager with a mocked Langfuse client.
    
    Returns:
        tuple: (manager, mock_client, created_traces, created_spans)
    """
    # Reset singleton first
    TracingManager.reset_instance()
    
    mock_client = MagicMock()
    created_traces = []
    created_spans = []
    
    def mock_trace(**kwargs):
        mock_trace_obj = MagicMock()
        mock_trace_obj.id = kwargs.get('id')
        mock_trace_obj.session_id = kwargs.get('session_id')
        created_traces.append({
            'id': kwargs.get('id'),
            'name': kwargs.get('name'),
            'session_id': kwargs.get('session_id'),
            'metadata': kwargs.get('metadata'),
            'mock': mock_trace_obj,
        })
        return mock_trace_obj
    
    def mock_span(**kwargs):
        mock_span_obj = MagicMock()
        mock_span_obj.id = kwargs.get('id')
        mock_span_obj.trace_id = kwargs.get('trace_id')
        created_spans.append({
            'id': kwargs.get('id'),
            'name': kwargs.get('name'),
            'trace_id': kwargs.get('trace_id'),
            'metadata': kwargs.get('metadata'),
            'mock': mock_span_obj,
        })
        return mock_span_obj
    
    mock_client.trace.side_effect = mock_trace
    mock_client.span.side_effect = mock_span
    
    config = LangfuseConfig(
        enabled=True,
        public_key="pk-test",
        secret_key="sk-test",
    )
    
    mock_langfuse_module = MagicMock()
    mock_langfuse_module.Langfuse.return_value = mock_client
    
    with patch.dict('sys.modules', {'langfuse': mock_langfuse_module}):
        manager = TracingManager(config)
    
    return manager, mock_client, created_traces, created_spans


# =============================================================================
# Property 4: Session Consistency
# =============================================================================

class TestProperty4SessionConsistency:
    """
    Feature: langfuse-evaluation-integration, Property 4: Session Consistency
    
    *For any* workflow execution with N threats generating attack trees, all created
    traces and spans SHALL share the same `session_id`, and querying by that
    `session_id` SHALL return all N+1 traces (1 parent + N tree traces).
    
    **Validates: Requirements 2.2, 8.1, 8.2, 8.4**
    """
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
    )
    def test_trace_preserves_session_id(
        self,
        workflow_name: str,
        session_id: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 4: Session Consistency
        
        Test that created traces preserve the provided session_id.
        
        **Validates: Requirements 2.2**
        """
        manager, mock_client, created_traces, _ = create_mocked_tracing_manager()
        
        trace = manager.create_trace(workflow_name, session_id)
        
        # Verify session_id is preserved in the trace object
        assert trace.session_id == session_id
        
        # Verify session_id was passed to Langfuse
        assert len(created_traces) == 1
        assert created_traces[0]['session_id'] == session_id
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        span_names=st.lists(span_name_strategy, min_size=1, max_size=10),
    )
    def test_all_spans_share_same_trace_id(
        self,
        workflow_name: str,
        session_id: str,
        span_names: List[str],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 4: Session Consistency
        
        Test that all spans within a trace share the same trace_id (which links to session_id).
        
        **Validates: Requirements 8.2**
        """
        manager, mock_client, created_traces, created_spans = create_mocked_tracing_manager()
        
        # Create parent trace
        trace = manager.create_trace(workflow_name, session_id)
        trace_id = trace.trace_id
        
        # Create multiple spans
        for span_name in span_names:
            span = manager.create_span(span_name, trace)
        
        # Verify all spans share the same trace_id
        assert len(created_spans) == len(span_names)
        for span_data in created_spans:
            assert span_data['trace_id'] == trace_id
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
    )
    def test_session_id_generated_when_not_provided(
        self,
        workflow_name: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 4: Session Consistency
        
        Test that TracingContext generates a unique session_id when not provided.
        
        **Validates: Requirements 8.1**
        """
        manager, mock_client, created_traces, _ = create_mocked_tracing_manager()
        ctx = TracingContext(manager)
        
        with ctx.trace(workflow_name) as trace:
            # Session ID should be generated
            assert ctx.current_session_id is not None
            assert len(ctx.current_session_id) == 36  # UUID format
            
            # Verify it's a valid UUID
            try:
                uuid.UUID(ctx.current_session_id)
            except ValueError:
                pytest.fail(f"Generated session_id '{ctx.current_session_id}' is not a valid UUID")
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        span_names=st.lists(span_name_strategy, min_size=1, max_size=5),
    )
    def test_session_id_propagated_to_all_child_spans_via_trace(
        self,
        workflow_name: str,
        session_id: str,
        span_names: List[str],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 4: Session Consistency
        
        Test that session_id is propagated to all child spans via the trace relationship.
        
        **Validates: Requirements 8.2**
        """
        manager, mock_client, created_traces, created_spans = create_mocked_tracing_manager()
        ctx = TracingContext(manager)
        
        with ctx.trace(workflow_name, session_id) as trace:
            # Verify session_id is stored in context
            assert ctx.current_session_id == session_id
            
            # Create child spans
            for span_name in span_names:
                with ctx.span(span_name) as span:
                    pass
        
        # Verify all spans were created with the same trace_id
        # (which links them to the session via the trace)
        assert len(created_spans) == len(span_names)
        trace_id = created_traces[0]['id']
        for span_data in created_spans:
            assert span_data['trace_id'] == trace_id
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        threat_count=threat_count_strategy,
    )
    def test_multiple_attack_tree_spans_share_session(
        self,
        workflow_name: str,
        session_id: str,
        threat_count: int,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 4: Session Consistency
        
        Test that N attack tree generation spans all share the same session_id
        via the parent trace.
        
        **Validates: Requirements 8.4**
        """
        manager, mock_client, created_traces, created_spans = create_mocked_tracing_manager()
        ctx = TracingContext(manager)
        
        with ctx.trace(workflow_name, session_id) as trace:
            # Simulate N threats generating attack trees
            for i in range(threat_count):
                with ctx.span(f"attack_tree_generation_{i}") as span:
                    span.set_input({"threat_id": f"threat_{i}"})
                    span.set_output({"attack_tree": f"tree_{i}"})
        
        # Verify we have N spans
        assert len(created_spans) == threat_count
        
        # Verify all spans share the same trace_id (linking to session)
        trace_id = created_traces[0]['id']
        for span_data in created_spans:
            assert span_data['trace_id'] == trace_id
        
        # Verify the trace has the correct session_id
        assert created_traces[0]['session_id'] == session_id
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        threat_count=threat_count_strategy,
    )
    def test_workflow_with_n_threats_creates_correct_trace_count(
        self,
        workflow_name: str,
        session_id: str,
        threat_count: int,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 4: Session Consistency
        
        Test that a workflow with N threats creates 1 parent trace and N+1 spans
        (context_analysis + N attack_tree_generation spans).
        
        **Validates: Requirements 8.4**
        """
        manager, mock_client, created_traces, created_spans = create_mocked_tracing_manager()
        ctx = TracingContext(manager)
        
        with ctx.trace(workflow_name, session_id) as trace:
            # Context analysis span
            with ctx.span("context_analysis") as span:
                span.set_input({"project_path": "/test"})
                span.set_output({"files": ["main.py"]})
            
            # N attack tree generation spans
            for i in range(threat_count):
                with ctx.span(f"attack_tree_generation") as span:
                    span.set_input({"threat_id": f"threat_{i}"})
                    span.set_output({"attack_tree": f"tree_{i}"})
        
        # Verify 1 parent trace
        assert len(created_traces) == 1
        
        # Verify N+1 spans (1 context_analysis + N attack_tree_generation)
        assert len(created_spans) == threat_count + 1
        
        # Verify all spans share the same trace_id
        trace_id = created_traces[0]['id']
        for span_data in created_spans:
            assert span_data['trace_id'] == trace_id
    
    @settings(max_examples=100)
    @given(
        execution_count=st.integers(min_value=2, max_value=10),
    )
    def test_different_workflow_executions_have_unique_session_ids(
        self,
        execution_count: int,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 4: Session Consistency
        
        Test that different workflow executions generate unique session_ids.
        
        **Validates: Requirements 8.1**
        """
        session_ids: Set[str] = set()
        
        for i in range(execution_count):
            manager, mock_client, created_traces, _ = create_mocked_tracing_manager()
            ctx = TracingContext(manager)
            
            with ctx.trace(f"workflow_{i}") as trace:
                session_ids.add(ctx.current_session_id)
        
        # All session_ids should be unique
        assert len(session_ids) == execution_count, (
            f"Expected {execution_count} unique session IDs, got {len(session_ids)}"
        )
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
    )
    def test_session_id_cleared_after_trace_context_exits(
        self,
        workflow_name: str,
        session_id: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 4: Session Consistency
        
        Test that session_id is cleared after trace context exits.
        
        **Validates: Requirements 8.1**
        """
        manager, mock_client, _, _ = create_mocked_tracing_manager()
        ctx = TracingContext(manager)
        
        with ctx.trace(workflow_name, session_id) as trace:
            assert ctx.current_session_id == session_id
        
        # Session ID should be cleared after context exits
        assert ctx.current_session_id is None
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
    )
    def test_nested_spans_all_link_to_same_trace(
        self,
        workflow_name: str,
        session_id: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 4: Session Consistency
        
        Test that nested spans all link to the same parent trace (and thus session).
        
        **Validates: Requirements 8.2**
        """
        manager, mock_client, created_traces, created_spans = create_mocked_tracing_manager()
        ctx = TracingContext(manager)
        
        with ctx.trace(workflow_name, session_id) as trace:
            with ctx.span("outer_span") as outer:
                with ctx.span("inner_span") as inner:
                    with ctx.span("innermost_span") as innermost:
                        pass
        
        # Verify all 3 spans were created
        assert len(created_spans) == 3
        
        # Verify all spans share the same trace_id
        trace_id = created_traces[0]['id']
        for span_data in created_spans:
            assert span_data['trace_id'] == trace_id


class TestSessionConsistencyWithNoOp:
    """
    Tests for session consistency behavior with NoOp implementations.
    
    **Validates: Requirements 2.2, 8.1, 8.2**
    """
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        threat_count=threat_count_strategy,
    )
    def test_noop_manager_handles_session_id_gracefully(
        self,
        workflow_name: str,
        session_id: str,
        threat_count: int,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 4: Session Consistency
        
        Test that NoOpTracingManager handles session_id without errors.
        
        **Validates: Requirements 2.2**
        """
        manager = NoOpTracingManager()
        ctx = TracingContext(manager)
        
        # Should not raise any exceptions
        with ctx.trace(workflow_name, session_id) as trace:
            assert isinstance(trace, NoOpTrace)
            
            for i in range(threat_count):
                with ctx.span(f"attack_tree_{i}") as span:
                    assert isinstance(span, NoOpSpan)
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
    )
    def test_noop_trace_returns_noop_session_id(
        self,
        workflow_name: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 4: Session Consistency
        
        Test that NoOpTrace returns "noop" for session_id.
        
        **Validates: Requirements 2.2**
        """
        trace = NoOpTrace()
        
        assert trace.session_id == "noop"
        assert trace.trace_id == "noop"
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
    )
    def test_noop_context_still_tracks_session_id(
        self,
        workflow_name: str,
        session_id: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 4: Session Consistency
        
        Test that TracingContext still tracks session_id even with NoOp manager.
        
        **Validates: Requirements 8.1**
        """
        manager = NoOpTracingManager()
        ctx = TracingContext(manager)
        
        with ctx.trace(workflow_name, session_id) as trace:
            # Context should still track the session_id
            assert ctx.current_session_id == session_id
        
        # Should be cleared after exit
        assert ctx.current_session_id is None


class TestSessionConsistencyEdgeCases:
    """
    Edge case tests for session consistency.
    
    **Validates: Requirements 2.2, 8.1, 8.2, 8.4**
    """
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
    )
    def test_span_without_trace_returns_noop(
        self,
        workflow_name: str,
        session_id: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 4: Session Consistency
        
        Test that creating a span without an active trace returns NoOpSpan.
        
        **Validates: Requirements 8.2**
        """
        manager, mock_client, _, created_spans = create_mocked_tracing_manager()
        ctx = TracingContext(manager)
        
        # Create span without trace context
        with ctx.span("orphan_span") as span:
            assert isinstance(span, NoOpSpan)
        
        # No spans should have been created in Langfuse
        assert len(created_spans) == 0
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
    )
    def test_exception_in_span_preserves_session_consistency(
        self,
        workflow_name: str,
        session_id: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 4: Session Consistency
        
        Test that exceptions in spans don't break session consistency.
        
        **Validates: Requirements 8.2**
        """
        manager, mock_client, created_traces, created_spans = create_mocked_tracing_manager()
        ctx = TracingContext(manager)
        
        with pytest.raises(ValueError):
            with ctx.trace(workflow_name, session_id) as trace:
                with ctx.span("span_1") as span1:
                    pass
                
                with ctx.span("span_2") as span2:
                    raise ValueError("Test error")
        
        # Both spans should have been created with same trace_id
        assert len(created_spans) == 2
        trace_id = created_traces[0]['id']
        for span_data in created_spans:
            assert span_data['trace_id'] == trace_id
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
    )
    def test_exception_in_trace_clears_session_id(
        self,
        workflow_name: str,
        session_id: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 4: Session Consistency
        
        Test that exceptions in trace context still clear session_id.
        
        **Validates: Requirements 8.1**
        """
        manager, mock_client, _, _ = create_mocked_tracing_manager()
        ctx = TracingContext(manager)
        
        with pytest.raises(ValueError):
            with ctx.trace(workflow_name, session_id) as trace:
                assert ctx.current_session_id == session_id
                raise ValueError("Test error")
        
        # Session ID should be cleared even after exception
        assert ctx.current_session_id is None
    
    @settings(max_examples=100)
    @given(
        session_id=session_id_strategy,
    )
    def test_empty_workflow_name_still_preserves_session(
        self,
        session_id: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 4: Session Consistency
        
        Test that session_id is preserved even with minimal workflow name.
        
        **Validates: Requirements 2.2**
        """
        manager, mock_client, created_traces, _ = create_mocked_tracing_manager()
        
        trace = manager.create_trace("w", session_id)
        
        assert trace.session_id == session_id
        assert created_traces[0]['session_id'] == session_id


class TestSessionConsistencyQueryability:
    """
    Tests for session_id queryability (simulated).
    
    These tests verify that session_id is properly set for querying purposes.
    
    **Validates: Requirements 2.2, 8.4**
    """
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        threat_count=threat_count_strategy,
    )
    def test_all_traces_and_spans_queryable_by_session_id(
        self,
        workflow_name: str,
        session_id: str,
        threat_count: int,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 4: Session Consistency
        
        Test that all traces and spans can be queried by session_id.
        
        This test simulates the queryability requirement by verifying that
        all created traces have the same session_id and all spans link to
        the trace (which has the session_id).
        
        **Validates: Requirements 2.2, 8.4**
        """
        manager, mock_client, created_traces, created_spans = create_mocked_tracing_manager()
        ctx = TracingContext(manager)
        
        with ctx.trace(workflow_name, session_id) as trace:
            # Create context analysis span
            with ctx.span("context_analysis") as span:
                pass
            
            # Create N attack tree spans
            for i in range(threat_count):
                with ctx.span("attack_tree_generation") as span:
                    pass
        
        # Verify 1 trace with correct session_id
        assert len(created_traces) == 1
        assert created_traces[0]['session_id'] == session_id
        
        # Verify N+1 spans all link to the trace
        expected_span_count = threat_count + 1
        assert len(created_spans) == expected_span_count
        
        trace_id = created_traces[0]['id']
        for span_data in created_spans:
            assert span_data['trace_id'] == trace_id
        
        # Simulate query: all spans can be found via trace_id -> session_id
        # In a real system, you would query Langfuse by session_id
        # Here we verify the data structure supports this
        queryable_by_session = {
            'session_id': session_id,
            'trace_id': trace_id,
            'span_count': len(created_spans),
        }
        
        assert queryable_by_session['session_id'] == session_id
        assert queryable_by_session['span_count'] == expected_span_count


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])
