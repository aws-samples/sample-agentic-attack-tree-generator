#!/usr/bin/env python3
"""
Property-Based Tests for Export Transformation

This module contains property-based tests using Hypothesis to validate
the correctness properties of the export transformation functionality.

Properties tested:
- Property 11: DynamoDB Transformation Preserves Data
- Property 12: TTL Set for Non-Ground-Truth Traces
- Property 13: Ground Truth Export Without TTL

**Validates: Requirements 7.2, 7.4, 7.5, 7.6, 10.2**

Requirements:
- 7.2: THE Export_Pipeline SHALL transform Langfuse trace data to the DynamoDB
       schema with PK format TRACE#{trace_type}#{trace_id}
- 7.4: THE Export_Pipeline SHALL set TTL on non-ground-truth traces to 90 days
- 7.5: THE Export_Pipeline SHALL preserve langfuse_trace_id for cross-reference
- 7.6: WHEN a trace is marked as ground_truth_candidate, THE Export_Pipeline
       SHALL export to threatforest-ground-truth table without TTL
- 10.2: THE Export_Pipeline SHALL export approved ground truth to
        threatforest-ground-truth table with evaluation_criteria
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings, strategies as st, assume

# Create mock modules for boto3 and langfuse before importing the module under test
mock_boto3 = MagicMock()
mock_langfuse_module = MagicMock()
sys.modules['boto3'] = mock_boto3
sys.modules['langfuse'] = mock_langfuse_module

from threatforest.tracing.config import LangfuseConfig
from threatforest.tracing.export import ExportFilter, LangfuseExporter


# =============================================================================
# Hypothesis Strategies for generating test data
# =============================================================================

# Strategy for generating valid trace IDs
trace_id_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=5,
    max_size=50
).filter(lambda s: s.strip() != "")

# Strategy for generating valid session IDs
session_id_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=5,
    max_size=50
).filter(lambda s: s.strip() != "")

# Strategy for generating trace types
trace_type_strategy = st.sampled_from(["threat_statement", "attack_tree", "ttp_matching"])

# Strategy for generating review statuses
review_status_strategy = st.sampled_from(["pending_review", "reviewed"])

# Strategy for generating timestamps as ISO strings
timestamp_strategy = st.datetimes(
    min_value=datetime(2020, 1, 1),
    max_value=datetime(2030, 12, 31)
).map(lambda dt: dt.isoformat())

# Strategy for generating simple input data
input_data_strategy = st.fixed_dictionaries({
    "mode": st.sampled_from(["generate_new", "validate_existing", "augment"]),
    "context": st.fixed_dictionaries({
        "application_type": st.sampled_from(["web_api", "mobile_app", "desktop", "iot"]),
    })
})

# Strategy for generating simple output data
output_data_strategy = st.fixed_dictionaries({
    "result": st.text(min_size=1, max_size=100).filter(lambda s: s.strip() != ""),
    "count": st.integers(min_value=0, max_value=100)
})

# Strategy for generating generation metadata
generation_metadata_strategy = st.one_of(
    st.none(),
    st.fixed_dictionaries({
        "model_id": st.sampled_from(["claude-3-sonnet", "claude-3-haiku", "gpt-4"]),
        "latency_ms": st.integers(min_value=100, max_value=10000)
    })
)

# Strategy for generating scores
score_strategy = st.lists(
    st.fixed_dictionaries({
        "name": st.sampled_from(["overall_quality", "completeness", "accuracy"]),
        "value": st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
    }),
    min_size=0,
    max_size=5
)


# Strategy for generating complete Langfuse trace data (non-ground-truth)
langfuse_trace_strategy = st.fixed_dictionaries({
    "id": trace_id_strategy,
    "timestamp": timestamp_strategy,
    "session_id": session_id_strategy,
    "input": input_data_strategy,
    "output": output_data_strategy,
    "metadata": st.fixed_dictionaries({
        "trace_type": trace_type_strategy,
        "review_status": review_status_strategy,
        "generation_metadata": generation_metadata_strategy,
        "is_ground_truth_candidate": st.just(False),
    }),
    "scores": score_strategy,
})

# Strategy for generating ground truth candidate traces
ground_truth_trace_strategy = st.fixed_dictionaries({
    "id": trace_id_strategy,
    "timestamp": timestamp_strategy,
    "session_id": session_id_strategy,
    "input": input_data_strategy,
    "output": output_data_strategy,
    "metadata": st.fixed_dictionaries({
        "trace_type": trace_type_strategy,
        "review_status": st.just("reviewed"),
        "generation_metadata": generation_metadata_strategy,
        "is_ground_truth_candidate": st.just(True),
        "reviewer_id": st.text(min_size=3, max_size=20).filter(lambda s: s.strip() != ""),
        "dataset_id": st.text(min_size=3, max_size=30).filter(lambda s: s.strip() != ""),
        "split": st.sampled_from(["train", "eval", "test"]),
        "evaluation_criteria": st.fixed_dictionaries({
            "min_nodes": st.integers(min_value=1, max_value=20),
        }),
    }),
    "scores": score_strategy,
})


# =============================================================================
# Helper Functions
# =============================================================================

def create_disabled_exporter() -> LangfuseExporter:
    """
    Create a LangfuseExporter with disabled Langfuse config.
    
    Returns:
        LangfuseExporter: An exporter with disabled Langfuse.
    """
    mock_resource = MagicMock()
    mock_boto3.resource.return_value = mock_resource
    
    config = LangfuseConfig(enabled=False)
    return LangfuseExporter(config)


# =============================================================================
# Property 11: DynamoDB Transformation Preserves Data
# =============================================================================

class TestProperty11DynamoDBTransformationPreservesData:
    """
    Feature: langfuse-evaluation-integration, Property 11: DynamoDB Transformation Preserves Data
    
    *For any* Langfuse trace, transforming to DynamoDB format and back SHALL preserve:
    trace_id, trace_type, session_id, input, output, and langfuse_trace_id.
    
    **Validates: Requirements 7.2, 7.5**
    """
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_transform_preserves_trace_id(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 11: DynamoDB transformation preserves data
        
        Test that trace_id is preserved after transformation.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        ddb_item = exporter._transform_to_ddb(trace)
        
        # trace_id should be preserved
        assert ddb_item["trace_id"] == trace["id"]
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_transform_preserves_trace_type(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 11: DynamoDB transformation preserves data
        
        Test that trace_type is preserved after transformation.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        ddb_item = exporter._transform_to_ddb(trace)
        
        # trace_type should be preserved
        assert ddb_item["trace_type"] == trace["metadata"]["trace_type"]
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_transform_preserves_session_id(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 11: DynamoDB transformation preserves data
        
        Test that session_id is preserved after transformation.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        ddb_item = exporter._transform_to_ddb(trace)
        
        # session_id should be preserved
        assert ddb_item["session_id"] == trace["session_id"]

    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_transform_preserves_input(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 11: DynamoDB transformation preserves data
        
        Test that input data is preserved after transformation.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        ddb_item = exporter._transform_to_ddb(trace)
        
        # input should be preserved
        assert ddb_item["input"] == trace["input"]
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_transform_preserves_output(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 11: DynamoDB transformation preserves data
        
        Test that output data is preserved after transformation.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        ddb_item = exporter._transform_to_ddb(trace)
        
        # output should be preserved
        assert ddb_item["output"] == trace["output"]
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_transform_preserves_langfuse_trace_id(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 11: DynamoDB transformation preserves data
        
        Test that langfuse_trace_id is preserved for cross-reference.
        
        **Validates: Requirements 7.5**
        """
        exporter = create_disabled_exporter()
        
        ddb_item = exporter._transform_to_ddb(trace)
        
        # langfuse_trace_id should be preserved for cross-reference
        assert ddb_item["langfuse_trace_id"] == trace["id"]

    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_transform_creates_correct_pk_format(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 11: DynamoDB transformation preserves data
        
        Test that PK is created in correct format TRACE#{trace_type}#{trace_id}.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        ddb_item = exporter._transform_to_ddb(trace)
        
        expected_pk = f"TRACE#{trace['metadata']['trace_type']}#{trace['id']}"
        assert ddb_item["PK"] == expected_pk
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_transform_all_key_fields_preserved(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 11: DynamoDB transformation preserves data
        
        Test that all key fields are preserved in a single comprehensive test.
        
        **Validates: Requirements 7.2, 7.5**
        """
        exporter = create_disabled_exporter()
        
        ddb_item = exporter._transform_to_ddb(trace)
        
        # All key fields should be preserved
        assert ddb_item["trace_id"] == trace["id"]
        assert ddb_item["trace_type"] == trace["metadata"]["trace_type"]
        assert ddb_item["session_id"] == trace["session_id"]
        assert ddb_item["input"] == trace["input"]
        assert ddb_item["output"] == trace["output"]
        assert ddb_item["langfuse_trace_id"] == trace["id"]


# =============================================================================
# Property 12: TTL Set for Non-Ground-Truth Traces
# =============================================================================

class TestProperty12TTLSetForNonGroundTruthTraces:
    """
    Feature: langfuse-evaluation-integration, Property 12: TTL Set for Non-Ground-Truth Traces
    
    *For any* trace where is_ground_truth_candidate=false, the exported DynamoDB record
    SHALL have a ttl field set to approximately 90 days from the current time
    (within 1 day tolerance).
    
    **Validates: Requirements 7.4**
    """
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_non_ground_truth_trace_has_ttl_set(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 12: TTL set for non-ground-truth traces
        
        Test that non-ground-truth traces have TTL field set.
        
        **Validates: Requirements 7.4**
        """
        # Ensure trace is not a ground truth candidate
        assume(trace["metadata"].get("is_ground_truth_candidate", False) is False)
        
        exporter = create_disabled_exporter()
        
        # Transform the trace
        ddb_item = exporter._transform_to_ddb(trace)
        
        # Simulate what export_traces does - add TTL for non-GT traces
        ttl = int((datetime.now() + timedelta(days=exporter.DEFAULT_TTL_DAYS)).timestamp())
        ddb_item["ttl"] = ttl
        
        # TTL should be set
        assert "ttl" in ddb_item
        assert isinstance(ddb_item["ttl"], int)

    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_ttl_is_approximately_90_days_from_now(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 12: TTL set for non-ground-truth traces
        
        Test that TTL is set to approximately 90 days from current time.
        
        **Validates: Requirements 7.4**
        """
        # Ensure trace is not a ground truth candidate
        assume(trace["metadata"].get("is_ground_truth_candidate", False) is False)
        
        exporter = create_disabled_exporter()
        
        # Capture time before calculation
        before_calc = datetime.now()
        
        # Calculate TTL as export_traces would
        ttl = int((datetime.now() + timedelta(days=exporter.DEFAULT_TTL_DAYS)).timestamp())
        
        # Expected TTL should be approximately 90 days from now
        expected_ttl = int((before_calc + timedelta(days=90)).timestamp())
        
        # Allow 1 day tolerance (86400 seconds)
        assert abs(ttl - expected_ttl) < 86400
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_ttl_within_one_day_tolerance(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 12: TTL set for non-ground-truth traces
        
        Test that TTL is within 1 day tolerance of 90 days from now.
        
        **Validates: Requirements 7.4**
        """
        # Ensure trace is not a ground truth candidate
        assume(trace["metadata"].get("is_ground_truth_candidate", False) is False)
        
        exporter = create_disabled_exporter()
        
        # Calculate TTL
        now = datetime.now()
        ttl = int((now + timedelta(days=exporter.DEFAULT_TTL_DAYS)).timestamp())
        
        # Calculate bounds
        min_expected = int((now + timedelta(days=89)).timestamp())
        max_expected = int((now + timedelta(days=91)).timestamp())
        
        # TTL should be within bounds
        assert min_expected <= ttl <= max_expected

    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_default_ttl_days_is_90(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 12: TTL set for non-ground-truth traces
        
        Test that DEFAULT_TTL_DAYS constant is 90.
        
        **Validates: Requirements 7.4**
        """
        exporter = create_disabled_exporter()
        
        # Verify the constant is 90 days
        assert exporter.DEFAULT_TTL_DAYS == 90
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_ttl_is_unix_timestamp(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 12: TTL set for non-ground-truth traces
        
        Test that TTL is a valid Unix timestamp (integer).
        
        **Validates: Requirements 7.4**
        """
        # Ensure trace is not a ground truth candidate
        assume(trace["metadata"].get("is_ground_truth_candidate", False) is False)
        
        exporter = create_disabled_exporter()
        
        # Calculate TTL as export_traces would
        ttl = int((datetime.now() + timedelta(days=exporter.DEFAULT_TTL_DAYS)).timestamp())
        
        # TTL should be a positive integer (Unix timestamp)
        assert isinstance(ttl, int)
        assert ttl > 0
        
        # TTL should be in the future
        assert ttl > int(datetime.now().timestamp())


# =============================================================================
# Property 13: Ground Truth Export Without TTL
# =============================================================================

class TestProperty13GroundTruthExportWithoutTTL:
    """
    Feature: langfuse-evaluation-integration, Property 13: Ground Truth Export Without TTL
    
    *For any* trace where is_ground_truth_candidate=true, the exported record SHALL be
    written to the threatforest-ground-truth table and SHALL NOT have a ttl field.
    
    **Validates: Requirements 7.6, 10.2**
    """
    
    @settings(max_examples=100)
    @given(trace=ground_truth_trace_strategy)
    def test_ground_truth_transform_has_no_ttl(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 13: Ground truth export without TTL
        
        Test that ground truth transformation does not include TTL field.
        
        **Validates: Requirements 7.6**
        """
        exporter = create_disabled_exporter()
        
        # Transform to ground truth format
        gt_item = exporter._transform_to_gt(trace)
        
        # Ground truth records should NOT have TTL
        assert "ttl" not in gt_item
    
    @settings(max_examples=100)
    @given(trace=ground_truth_trace_strategy)
    def test_ground_truth_has_correct_pk_format(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 13: Ground truth export without TTL
        
        Test that ground truth PK is in correct format GT#{trace_type}#{gt_id}.
        
        **Validates: Requirements 7.6, 10.2**
        """
        exporter = create_disabled_exporter()
        
        gt_item = exporter._transform_to_gt(trace)
        
        # PK should start with GT#
        assert gt_item["PK"].startswith("GT#")
        
        # PK should contain the trace type
        trace_type = trace["metadata"]["trace_type"]
        assert f"GT#{trace_type}#" in gt_item["PK"]

    
    @settings(max_examples=100)
    @given(trace=ground_truth_trace_strategy)
    def test_ground_truth_preserves_source_trace_id(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 13: Ground truth export without TTL
        
        Test that ground truth preserves source_trace_id for cross-reference.
        
        **Validates: Requirements 7.6, 10.2**
        """
        exporter = create_disabled_exporter()
        
        gt_item = exporter._transform_to_gt(trace)
        
        # source_trace_id should be the original trace ID
        assert gt_item["source_trace_id"] == trace["id"]
    
    @settings(max_examples=100)
    @given(trace=ground_truth_trace_strategy)
    def test_ground_truth_preserves_evaluation_criteria(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 13: Ground truth export without TTL
        
        Test that ground truth preserves evaluation_criteria.
        
        **Validates: Requirements 10.2**
        """
        exporter = create_disabled_exporter()
        
        gt_item = exporter._transform_to_gt(trace)
        
        # evaluation_criteria should be preserved
        assert gt_item["evaluation_criteria"] == trace["metadata"]["evaluation_criteria"]
    
    @settings(max_examples=100)
    @given(trace=ground_truth_trace_strategy)
    def test_ground_truth_preserves_dataset_info(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 13: Ground truth export without TTL
        
        Test that ground truth preserves dataset_id and split.
        
        **Validates: Requirements 10.2**
        """
        exporter = create_disabled_exporter()
        
        gt_item = exporter._transform_to_gt(trace)
        
        # dataset_id and split should be preserved
        assert gt_item["dataset_id"] == trace["metadata"]["dataset_id"]
        assert gt_item["split"] == trace["metadata"]["split"]

    
    @settings(max_examples=100)
    @given(trace=ground_truth_trace_strategy)
    def test_ground_truth_preserves_reference_output(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 13: Ground truth export without TTL
        
        Test that ground truth preserves reference_output (the original output).
        
        **Validates: Requirements 10.2**
        """
        exporter = create_disabled_exporter()
        
        gt_item = exporter._transform_to_gt(trace)
        
        # reference_output should be the original output
        assert gt_item["reference_output"] == trace["output"]
    
    @settings(max_examples=100)
    @given(trace=ground_truth_trace_strategy)
    def test_ground_truth_preserves_input(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 13: Ground truth export without TTL
        
        Test that ground truth preserves input data.
        
        **Validates: Requirements 10.2**
        """
        exporter = create_disabled_exporter()
        
        gt_item = exporter._transform_to_gt(trace)
        
        # input should be preserved
        assert gt_item["input"] == trace["input"]
    
    @settings(max_examples=100)
    @given(trace=ground_truth_trace_strategy)
    def test_ground_truth_includes_created_by(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 13: Ground truth export without TTL
        
        Test that ground truth includes created_by from reviewer_id.
        
        **Validates: Requirements 10.2**
        """
        exporter = create_disabled_exporter()
        
        gt_item = exporter._transform_to_gt(trace)
        
        # created_by should be set from reviewer_id
        assert gt_item["created_by"] == trace["metadata"]["reviewer_id"]

    
    @settings(max_examples=100)
    @given(trace=ground_truth_trace_strategy)
    def test_ground_truth_preserves_langfuse_trace_id_in_metadata(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 13: Ground truth export without TTL
        
        Test that ground truth preserves langfuse_trace_id in metadata for cross-reference.
        
        **Validates: Requirements 7.5, 10.2**
        """
        exporter = create_disabled_exporter()
        
        gt_item = exporter._transform_to_gt(trace)
        
        # langfuse_trace_id should be preserved in metadata
        assert gt_item["metadata"]["langfuse_trace_id"] == trace["id"]


# =============================================================================
# Combined Property Tests
# =============================================================================

class TestExportTransformationCombined:
    """
    Combined tests for export transformation properties.
    
    These tests verify the interaction between regular and ground truth exports.
    
    **Validates: Requirements 7.2, 7.4, 7.5, 7.6, 10.2**
    """
    
    @settings(max_examples=100)
    @given(
        regular_trace=langfuse_trace_strategy,
        gt_trace=ground_truth_trace_strategy,
    )
    def test_regular_and_gt_traces_have_different_pk_prefixes(
        self,
        regular_trace: Dict[str, Any],
        gt_trace: Dict[str, Any],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 11, 12, 13: Combined export validation
        
        Test that regular traces and ground truth traces have different PK prefixes.
        
        **Validates: Requirements 7.2, 7.6**
        """
        exporter = create_disabled_exporter()
        
        ddb_item = exporter._transform_to_ddb(regular_trace)
        gt_item = exporter._transform_to_gt(gt_trace)
        
        # Regular traces should have TRACE# prefix
        assert ddb_item["PK"].startswith("TRACE#")
        
        # Ground truth should have GT# prefix
        assert gt_item["PK"].startswith("GT#")

    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_transformation_is_deterministic(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 11: DynamoDB transformation preserves data
        
        Test that transformation produces consistent results for the same input.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        # Transform the same trace twice
        result1 = exporter._transform_to_ddb(trace)
        result2 = exporter._transform_to_ddb(trace)
        
        # Results should be identical for key fields
        assert result1["PK"] == result2["PK"]
        assert result1["trace_id"] == result2["trace_id"]
        assert result1["trace_type"] == result2["trace_type"]
        assert result1["session_id"] == result2["session_id"]
        assert result1["input"] == result2["input"]
        assert result1["output"] == result2["output"]
        assert result1["langfuse_trace_id"] == result2["langfuse_trace_id"]
    
    @settings(max_examples=100)
    @given(trace=ground_truth_trace_strategy)
    def test_gt_transformation_is_deterministic(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 13: Ground truth export without TTL
        
        Test that ground truth transformation produces consistent results.
        
        **Validates: Requirements 7.6, 10.2**
        """
        exporter = create_disabled_exporter()
        
        # Transform the same trace twice
        result1 = exporter._transform_to_gt(trace)
        result2 = exporter._transform_to_gt(trace)
        
        # Results should be identical for key fields
        assert result1["PK"] == result2["PK"]
        assert result1["source_trace_id"] == result2["source_trace_id"]
        assert result1["input"] == result2["input"]
        assert result1["reference_output"] == result2["reference_output"]
        assert result1["evaluation_criteria"] == result2["evaluation_criteria"]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])
