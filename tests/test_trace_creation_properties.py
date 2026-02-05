#!/usr/bin/env python3
"""
Property-Based Tests for Trace Creation

This module contains property-based tests using Hypothesis to validate
the correctness properties of trace creation in the Langfuse tracing module.

Properties tested:
- Property 3: Trace Creation Uniqueness
- Property 5: Trace Status Reflects Outcome

**Validates: Requirements 2.1, 2.3, 2.4, 2.5**

Requirements:
- 2.1: WHEN a ThreatForest workflow starts, THE Tracing_Module SHALL create a parent trace with a unique trace_id
- 2.3: THE Tracing_Module SHALL capture workflow metadata including bedrock_model, project_path, and timestamp
- 2.4: WHEN the workflow completes, THE Tracing_Module SHALL mark the trace as complete with final status
- 2.5: IF the workflow fails, THEN THE Tracing_Module SHALL capture the error details and mark the trace as failed
"""

import sys
from pathlib import Path
from typing import Any, Dict, Set
from unittest.mock import MagicMock, patch
from datetime import datetime

import pytest
from hypothesis import given, settings, strategies as st

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from threatforest.tracing.config import LangfuseConfig
from threatforest.tracing.manager import (
    TracingManager,
    LangfuseTrace,
    get_tracing_manager,
)
from threatforest.tracing.noop import NoOpTrace, NoOpTracingManager


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
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S")),
    min_size=1,
    max_size=100
).filter(lambda s: s.strip() != "")

# Strategy for generating bedrock model names
bedrock_model_strategy = st.sampled_from([
    "anthropic.claude-3-sonnet-20240229-v1:0",
    "anthropic.claude-3-haiku-20240307-v1:0",
    "anthropic.claude-3-opus-20240229-v1:0",
    "amazon.titan-text-express-v1",
    "meta.llama3-70b-instruct-v1:0",
])

# Strategy for generating project paths
project_path_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P")),
    min_size=1,
    max_size=200
).map(lambda s: f"/path/to/{s.replace(' ', '_')}")

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
    max_size=20
)

# Strategy for generating error messages
error_message_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S")),
    min_size=1,
    max_size=500
).filter(lambda s: s.strip() != "")


# =============================================================================
# Helper function to create a TracingManager with mocked Langfuse
# =============================================================================

def create_mocked_tracing_manager():
    """
    Create a TracingManager with a mocked Langfuse client.
    
    Returns:
        tuple: (manager, mock_client, mock_langfuse_trace)
    """
    # Reset singleton first
    TracingManager.reset_instance()
    
    mock_client = MagicMock()
    mock_langfuse_trace = MagicMock()
    mock_client.trace.return_value = mock_langfuse_trace
    
    config = LangfuseConfig(
        enabled=True,
        public_key="pk-test",
        secret_key="sk-test",
    )
    
    mock_langfuse_module = MagicMock()
    mock_langfuse_module.Langfuse.return_value = mock_client
    
    with patch.dict('sys.modules', {'langfuse': mock_langfuse_module}):
        manager = TracingManager(config)
    
    return manager, mock_client, mock_langfuse_trace


# =============================================================================
# Property 3: Trace Creation Uniqueness
# =============================================================================

class TestProperty3TraceCreationUniqueness:
    """
    Feature: langfuse-evaluation-integration, Property 3: Trace Creation Uniqueness
    
    *For any* workflow execution, the created trace SHALL have a non-empty `trace_id`
    that is unique across all traces, and SHALL include `bedrock_model`, `project_path`,
    and `timestamp` in metadata.
    
    **Validates: Requirements 2.1, 2.3**
    """
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        bedrock_model=bedrock_model_strategy,
        project_path=project_path_strategy,
    )
    def test_trace_id_is_non_empty(
        self,
        workflow_name: str,
        session_id: str,
        bedrock_model: str,
        project_path: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 3: Trace Creation Uniqueness
        
        Test that created traces have non-empty trace_id values.
        
        **Validates: Requirements 2.1**
        """
        manager, mock_client, _ = create_mocked_tracing_manager()
        
        metadata = {
            "bedrock_model": bedrock_model,
            "project_path": project_path,
        }
        
        trace = manager.create_trace(workflow_name, session_id, metadata)
        
        # Verify trace_id is non-empty
        assert trace.trace_id is not None
        assert len(trace.trace_id) > 0
        assert trace.trace_id != ""
        assert trace.trace_id != "noop"  # Should be a real UUID, not noop
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        trace_count=st.integers(min_value=2, max_value=20),
    )
    def test_trace_ids_are_unique(
        self,
        workflow_name: str,
        session_id: str,
        trace_count: int,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 3: Trace Creation Uniqueness
        
        Test that multiple traces created have unique trace_id values.
        
        **Validates: Requirements 2.1**
        """
        trace_ids: Set[str] = set()
        
        for i in range(trace_count):
            manager, mock_client, _ = create_mocked_tracing_manager()
            
            trace = manager.create_trace(
                f"{workflow_name}_{i}",
                f"{session_id}_{i}",
                {"iteration": i}
            )
            
            trace_ids.add(trace.trace_id)
        
        # All trace_ids should be unique
        assert len(trace_ids) == trace_count, (
            f"Expected {trace_count} unique trace IDs, got {len(trace_ids)}"
        )
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        bedrock_model=bedrock_model_strategy,
        project_path=project_path_strategy,
    )
    def test_trace_metadata_includes_timestamp(
        self,
        workflow_name: str,
        session_id: str,
        bedrock_model: str,
        project_path: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 3: Trace Creation Uniqueness
        
        Test that created traces include timestamp in metadata.
        
        **Validates: Requirements 2.3**
        """
        manager, mock_client, _ = create_mocked_tracing_manager()
        
        metadata = {
            "bedrock_model": bedrock_model,
            "project_path": project_path,
        }
        
        trace = manager.create_trace(workflow_name, session_id, metadata)
        
        # Verify trace() was called with metadata containing timestamp
        mock_client.trace.assert_called_once()
        call_kwargs = mock_client.trace.call_args[1]
        
        assert "metadata" in call_kwargs
        assert "timestamp" in call_kwargs["metadata"]
        
        # Verify timestamp is a valid ISO format string
        timestamp = call_kwargs["metadata"]["timestamp"]
        assert timestamp is not None
        assert len(timestamp) > 0
        
        # Verify it can be parsed as ISO datetime
        try:
            datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            pytest.fail(f"Timestamp '{timestamp}' is not valid ISO format")
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        bedrock_model=bedrock_model_strategy,
        project_path=project_path_strategy,
    )
    def test_trace_metadata_preserves_bedrock_model_and_project_path(
        self,
        workflow_name: str,
        session_id: str,
        bedrock_model: str,
        project_path: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 3: Trace Creation Uniqueness
        
        Test that created traces preserve bedrock_model and project_path in metadata.
        
        **Validates: Requirements 2.3**
        """
        manager, mock_client, _ = create_mocked_tracing_manager()
        
        metadata = {
            "bedrock_model": bedrock_model,
            "project_path": project_path,
        }
        
        trace = manager.create_trace(workflow_name, session_id, metadata)
        
        # Verify trace() was called with metadata containing bedrock_model and project_path
        mock_client.trace.assert_called_once()
        call_kwargs = mock_client.trace.call_args[1]
        
        assert "metadata" in call_kwargs
        assert call_kwargs["metadata"]["bedrock_model"] == bedrock_model
        assert call_kwargs["metadata"]["project_path"] == project_path
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
    )
    def test_trace_session_id_is_preserved(
        self,
        workflow_name: str,
        session_id: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 3: Trace Creation Uniqueness
        
        Test that created traces preserve the session_id.
        
        **Validates: Requirements 2.1**
        """
        manager, mock_client, _ = create_mocked_tracing_manager()
        
        trace = manager.create_trace(workflow_name, session_id)
        
        # Verify session_id is preserved
        assert trace.session_id == session_id
        
        # Verify trace() was called with correct session_id
        mock_client.trace.assert_called_once()
        call_kwargs = mock_client.trace.call_args[1]
        assert call_kwargs["session_id"] == session_id
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
    )
    def test_trace_id_is_valid_uuid_format(
        self,
        workflow_name: str,
        session_id: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 3: Trace Creation Uniqueness
        
        Test that trace_id is in valid UUID format.
        
        **Validates: Requirements 2.1**
        """
        import uuid
        
        manager, mock_client, _ = create_mocked_tracing_manager()
        
        trace = manager.create_trace(workflow_name, session_id)
        
        # Verify trace_id is valid UUID format
        try:
            uuid.UUID(trace.trace_id)
        except ValueError:
            pytest.fail(f"trace_id '{trace.trace_id}' is not a valid UUID")


# =============================================================================
# Property 5: Trace Status Reflects Outcome
# =============================================================================

class TestProperty5TraceStatusReflectsOutcome:
    """
    Feature: langfuse-evaluation-integration, Property 5: Trace Status Reflects Outcome
    
    *For any* workflow execution, IF the workflow completes successfully THEN the trace
    status SHALL be "success", and IF the workflow raises an exception THEN the trace
    status SHALL be "error" with the error message captured.
    
    **Validates: Requirements 2.4, 2.5**
    """
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
    )
    def test_successful_workflow_sets_success_status(
        self,
        workflow_name: str,
        session_id: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 5: Trace Status Reflects Outcome
        
        Test that successful workflow completion sets trace status to "success".
        
        **Validates: Requirements 2.4**
        """
        mock_langfuse_trace = MagicMock()
        
        trace = LangfuseTrace(
            langfuse_trace=mock_langfuse_trace,
            trace_id="test-trace-id",
            session_id=session_id,
        )
        
        # Simulate successful workflow completion
        trace.set_status("success")
        
        # Verify status was set correctly
        mock_langfuse_trace.update.assert_called_once()
        call_kwargs = mock_langfuse_trace.update.call_args[1]
        assert call_kwargs["status_message"] == "success"
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        error_message=error_message_strategy,
    )
    def test_failed_workflow_sets_error_status_with_message(
        self,
        workflow_name: str,
        session_id: str,
        error_message: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 5: Trace Status Reflects Outcome
        
        Test that failed workflow sets trace status to "error" with error message captured.
        
        **Validates: Requirements 2.5**
        """
        mock_langfuse_trace = MagicMock()
        
        trace = LangfuseTrace(
            langfuse_trace=mock_langfuse_trace,
            trace_id="test-trace-id",
            session_id=session_id,
        )
        
        # Simulate failed workflow
        trace.set_status("error", error_message)
        
        # Verify status was set correctly with error message
        mock_langfuse_trace.update.assert_called_once()
        call_kwargs = mock_langfuse_trace.update.call_args[1]
        assert call_kwargs["status_message"] == "error"
        assert "metadata" in call_kwargs
        assert call_kwargs["metadata"]["error"] == error_message
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
    )
    def test_error_status_without_message_does_not_include_error_metadata(
        self,
        workflow_name: str,
        session_id: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 5: Trace Status Reflects Outcome
        
        Test that error status without message does not include error in metadata.
        
        **Validates: Requirements 2.5**
        """
        mock_langfuse_trace = MagicMock()
        
        trace = LangfuseTrace(
            langfuse_trace=mock_langfuse_trace,
            trace_id="test-trace-id",
            session_id=session_id,
        )
        
        # Simulate error without message
        trace.set_status("error")
        
        # Verify status was set without error metadata
        mock_langfuse_trace.update.assert_called_once()
        call_kwargs = mock_langfuse_trace.update.call_args[1]
        assert call_kwargs["status_message"] == "error"
        # Should not have metadata with error key when no error message provided
        assert "metadata" not in call_kwargs or "error" not in call_kwargs.get("metadata", {})
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        error_message=error_message_strategy,
        additional_metadata=metadata_strategy,
    )
    def test_error_status_preserves_existing_metadata(
        self,
        workflow_name: str,
        session_id: str,
        error_message: str,
        additional_metadata: Dict[str, Any],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 5: Trace Status Reflects Outcome
        
        Test that setting error status preserves any existing metadata.
        
        **Validates: Requirements 2.5**
        """
        mock_langfuse_trace = MagicMock()
        
        trace = LangfuseTrace(
            langfuse_trace=mock_langfuse_trace,
            trace_id="test-trace-id",
            session_id=session_id,
        )
        
        # Add some metadata first
        for key, value in additional_metadata.items():
            trace.add_metadata(key, value)
        
        # Reset mock to track only the set_status call
        mock_langfuse_trace.reset_mock()
        
        # Simulate failed workflow
        trace.set_status("error", error_message)
        
        # Verify error message is captured
        mock_langfuse_trace.update.assert_called_once()
        call_kwargs = mock_langfuse_trace.update.call_args[1]
        assert call_kwargs["status_message"] == "error"
        assert call_kwargs["metadata"]["error"] == error_message
        
        # Verify existing metadata is preserved
        for key, value in additional_metadata.items():
            assert call_kwargs["metadata"][key] == value
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        output_data=metadata_strategy,
    )
    def test_successful_workflow_can_set_output_before_status(
        self,
        workflow_name: str,
        session_id: str,
        output_data: Dict[str, Any],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 5: Trace Status Reflects Outcome
        
        Test that output can be set before setting success status.
        
        **Validates: Requirements 2.4**
        """
        mock_langfuse_trace = MagicMock()
        
        trace = LangfuseTrace(
            langfuse_trace=mock_langfuse_trace,
            trace_id="test-trace-id",
            session_id=session_id,
        )
        
        # Set output first
        trace.set_output(output_data)
        
        # Then set success status
        trace.set_status("success")
        
        # Verify both calls were made
        assert mock_langfuse_trace.update.call_count == 2
        
        # First call should be set_output
        first_call_kwargs = mock_langfuse_trace.update.call_args_list[0][1]
        assert first_call_kwargs["output"] == output_data
        
        # Second call should be set_status
        second_call_kwargs = mock_langfuse_trace.update.call_args_list[1][1]
        assert second_call_kwargs["status_message"] == "success"
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
    )
    def test_noop_trace_set_status_does_not_raise(
        self,
        workflow_name: str,
        session_id: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 5: Trace Status Reflects Outcome
        
        Test that NoOpTrace.set_status() does not raise exceptions.
        
        **Validates: Requirements 2.4, 2.5**
        """
        trace = NoOpTrace()
        
        # Should not raise for success
        trace.set_status("success")
        
        # Should not raise for error with message
        trace.set_status("error", "Some error occurred")
        
        # Should not raise for error without message
        trace.set_status("error")
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        error_message=error_message_strategy,
    )
    def test_error_message_is_captured_exactly(
        self,
        workflow_name: str,
        session_id: str,
        error_message: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 5: Trace Status Reflects Outcome
        
        Test that error message is captured exactly as provided.
        
        **Validates: Requirements 2.5**
        """
        mock_langfuse_trace = MagicMock()
        
        trace = LangfuseTrace(
            langfuse_trace=mock_langfuse_trace,
            trace_id="test-trace-id",
            session_id=session_id,
        )
        
        # Set error status with message
        trace.set_status("error", error_message)
        
        # Verify error message is captured exactly
        call_kwargs = mock_langfuse_trace.update.call_args[1]
        assert call_kwargs["metadata"]["error"] == error_message


# =============================================================================
# End-to-End Trace Creation Tests
# =============================================================================

class TestTraceCreationEndToEnd:
    """
    End-to-end tests for trace creation combining Property 3 and Property 5.
    
    These tests verify the complete trace lifecycle from creation to status setting.
    
    **Validates: Requirements 2.1, 2.3, 2.4, 2.5**
    """
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        bedrock_model=bedrock_model_strategy,
        project_path=project_path_strategy,
        output_data=metadata_strategy,
    )
    def test_complete_successful_trace_lifecycle(
        self,
        workflow_name: str,
        session_id: str,
        bedrock_model: str,
        project_path: str,
        output_data: Dict[str, Any],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 3 & 5: Complete trace lifecycle
        
        Test complete trace lifecycle for successful workflow.
        
        **Validates: Requirements 2.1, 2.3, 2.4**
        """
        manager, mock_client, mock_langfuse_trace = create_mocked_tracing_manager()
        
        # Create trace with metadata
        metadata = {
            "bedrock_model": bedrock_model,
            "project_path": project_path,
        }
        trace = manager.create_trace(workflow_name, session_id, metadata)
        
        # Verify trace was created with unique ID
        assert trace.trace_id is not None
        assert len(trace.trace_id) > 0
        assert trace.session_id == session_id
        
        # Set output
        trace.set_output(output_data)
        
        # Set success status
        trace.set_status("success")
        
        # Flush
        manager.flush()
        
        # Verify trace creation included timestamp
        create_call_kwargs = mock_client.trace.call_args[1]
        assert "timestamp" in create_call_kwargs["metadata"]
        assert create_call_kwargs["metadata"]["bedrock_model"] == bedrock_model
        assert create_call_kwargs["metadata"]["project_path"] == project_path
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
        bedrock_model=bedrock_model_strategy,
        project_path=project_path_strategy,
        error_message=error_message_strategy,
    )
    def test_complete_failed_trace_lifecycle(
        self,
        workflow_name: str,
        session_id: str,
        bedrock_model: str,
        project_path: str,
        error_message: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 3 & 5: Complete trace lifecycle
        
        Test complete trace lifecycle for failed workflow.
        
        **Validates: Requirements 2.1, 2.3, 2.5**
        """
        manager, mock_client, mock_langfuse_trace = create_mocked_tracing_manager()
        
        # Create trace with metadata
        metadata = {
            "bedrock_model": bedrock_model,
            "project_path": project_path,
        }
        trace = manager.create_trace(workflow_name, session_id, metadata)
        
        # Verify trace was created with unique ID
        assert trace.trace_id is not None
        assert len(trace.trace_id) > 0
        
        # Set error status with message
        trace.set_status("error", error_message)
        
        # Flush
        manager.flush()
        
        # Verify error was captured
        status_call_kwargs = mock_langfuse_trace.update.call_args[1]
        assert status_call_kwargs["status_message"] == "error"
        assert status_call_kwargs["metadata"]["error"] == error_message
    
    @settings(max_examples=100)
    @given(
        workflow_name=workflow_name_strategy,
        session_id=session_id_strategy,
    )
    def test_disabled_tracing_complete_lifecycle(
        self,
        workflow_name: str,
        session_id: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 3 & 5: Disabled tracing lifecycle
        
        Test that disabled tracing completes lifecycle without errors.
        
        **Validates: Requirements 2.1, 2.4, 2.5**
        """
        # Reset singleton
        TracingManager.reset_instance()
        
        config = LangfuseConfig(enabled=False)
        manager = get_tracing_manager(config)
        
        # Create trace
        trace = manager.create_trace(workflow_name, session_id)
        
        # Verify NoOp trace
        assert isinstance(trace, NoOpTrace)
        assert trace.trace_id == "noop"
        
        # Set output and status - should not raise
        trace.set_output({"result": "test"})
        trace.set_status("success")
        
        # Flush - should not raise
        manager.flush()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])
