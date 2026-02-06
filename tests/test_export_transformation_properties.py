#!/usr/bin/env python3
"""
Property-Based Tests for Export Transformation

This module contains property-based tests using Hypothesis to validate
the correctness properties of the export transformation functionality
for Langfuse Datasets.

Properties tested:
- Property 11: Dataset Item Transformation Preserves Data
- Property 12: Dataset Item Metadata Completeness
- Property 13: Ground Truth Candidate Handling

**Validates: Requirements 7.2, 7.5**

Requirements:
- 7.2: THE Export_Pipeline SHALL transform Langfuse trace data to dataset items
       with input/expected_output pairs
- 7.5: THE Export_Pipeline SHALL preserve langfuse_trace_id for cross-reference
"""

from datetime import datetime
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings, strategies as st, assume

from threatforest.tracing.config import LangfuseConfig
from threatforest.tracing.export import ExportFilter, LangfuseDatasetExporter


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
        "evaluation_criteria": st.fixed_dictionaries({
            "min_nodes": st.integers(min_value=1, max_value=20),
        }),
    }),
    "scores": score_strategy,
})


# =============================================================================
# Helper Functions
# =============================================================================

def create_disabled_exporter() -> LangfuseDatasetExporter:
    """
    Create a LangfuseDatasetExporter with disabled Langfuse config.
    
    Returns:
        LangfuseDatasetExporter: An exporter with disabled Langfuse.
    """
    config = LangfuseConfig(enabled=False)
    with patch.object(LangfuseDatasetExporter, '_init_langfuse', return_value=None):
        return LangfuseDatasetExporter(config)


# =============================================================================
# Property 11: Dataset Item Transformation Preserves Data
# =============================================================================

class TestProperty11DatasetItemTransformationPreservesData:
    """
    Feature: langfuse-evaluation-integration, Property 11: Dataset Item Transformation Preserves Data
    
    *For any* Langfuse trace, transforming to dataset item format SHALL preserve:
    input, output (as expected_output), and langfuse_trace_id.
    
    **Validates: Requirements 7.2, 7.5**
    """
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_transform_preserves_input(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 11: Dataset item transformation preserves data
        
        Test that input is preserved after transformation.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        dataset_item = exporter._transform_to_dataset_item(trace)
        
        # input should be preserved
        assert dataset_item["input"] == trace["input"]
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_transform_preserves_output_as_expected_output(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 11: Dataset item transformation preserves data
        
        Test that output becomes expected_output after transformation.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        dataset_item = exporter._transform_to_dataset_item(trace)
        
        # output should become expected_output
        assert dataset_item["expected_output"] == trace["output"]
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_transform_preserves_langfuse_trace_id(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 11: Dataset item transformation preserves data
        
        Test that langfuse_trace_id is preserved in metadata for cross-reference.
        
        **Validates: Requirements 7.5**
        """
        exporter = create_disabled_exporter()
        
        dataset_item = exporter._transform_to_dataset_item(trace)
        
        # langfuse_trace_id should be preserved in metadata
        assert dataset_item["metadata"]["langfuse_trace_id"] == trace["id"]
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_transform_preserves_trace_type(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 11: Dataset item transformation preserves data
        
        Test that trace_type is preserved in metadata.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        dataset_item = exporter._transform_to_dataset_item(trace)
        
        # trace_type should be preserved in metadata
        assert dataset_item["metadata"]["trace_type"] == trace["metadata"]["trace_type"]
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_transform_preserves_session_id(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 11: Dataset item transformation preserves data
        
        Test that session_id is preserved in metadata.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        dataset_item = exporter._transform_to_dataset_item(trace)
        
        # session_id should be preserved in metadata
        assert dataset_item["metadata"]["session_id"] == trace["session_id"]
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_transform_preserves_review_status(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 11: Dataset item transformation preserves data
        
        Test that review_status is preserved in metadata.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        dataset_item = exporter._transform_to_dataset_item(trace)
        
        # review_status should be preserved in metadata
        assert dataset_item["metadata"]["review_status"] == trace["metadata"]["review_status"]
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_transform_all_key_fields_preserved(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 11: Dataset item transformation preserves data
        
        Test that all key fields are preserved in a single comprehensive test.
        
        **Validates: Requirements 7.2, 7.5**
        """
        exporter = create_disabled_exporter()
        
        dataset_item = exporter._transform_to_dataset_item(trace)
        
        # All key fields should be preserved
        assert dataset_item["input"] == trace["input"]
        assert dataset_item["expected_output"] == trace["output"]
        assert dataset_item["metadata"]["langfuse_trace_id"] == trace["id"]
        assert dataset_item["metadata"]["trace_type"] == trace["metadata"]["trace_type"]
        assert dataset_item["metadata"]["session_id"] == trace["session_id"]
        assert dataset_item["metadata"]["review_status"] == trace["metadata"]["review_status"]


# =============================================================================
# Property 12: Dataset Item Metadata Completeness
# =============================================================================

class TestProperty12DatasetItemMetadataCompleteness:
    """
    Feature: langfuse-evaluation-integration, Property 12: Dataset Item Metadata Completeness
    
    *For any* trace, the transformed dataset item SHALL include complete metadata
    including scores, generation_metadata, and timestamps.
    
    **Validates: Requirements 7.2**
    """
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_metadata_includes_scores(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 12: Dataset item metadata completeness
        
        Test that scores are included in metadata.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        dataset_item = exporter._transform_to_dataset_item(trace)
        
        # scores should be included in metadata
        assert "scores" in dataset_item["metadata"]
        assert isinstance(dataset_item["metadata"]["scores"], list)
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_metadata_includes_generation_metadata(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 12: Dataset item metadata completeness
        
        Test that generation_metadata is included in metadata.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        dataset_item = exporter._transform_to_dataset_item(trace)
        
        # generation_metadata should be included in metadata
        assert "generation_metadata" in dataset_item["metadata"]
        assert dataset_item["metadata"]["generation_metadata"] == trace["metadata"]["generation_metadata"]
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_metadata_includes_created_at(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 12: Dataset item metadata completeness
        
        Test that created_at timestamp is included in metadata.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        dataset_item = exporter._transform_to_dataset_item(trace)
        
        # created_at should be included in metadata
        assert "created_at" in dataset_item["metadata"]
        assert dataset_item["metadata"]["created_at"] == trace["timestamp"]
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_metadata_includes_ground_truth_flag(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 12: Dataset item metadata completeness
        
        Test that is_ground_truth_candidate flag is included in metadata.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        dataset_item = exporter._transform_to_dataset_item(trace)
        
        # is_ground_truth_candidate should be included in metadata
        assert "is_ground_truth_candidate" in dataset_item["metadata"]
        assert dataset_item["metadata"]["is_ground_truth_candidate"] == trace["metadata"]["is_ground_truth_candidate"]
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_scores_are_properly_extracted(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 12: Dataset item metadata completeness
        
        Test that scores are properly extracted with name and value.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        dataset_item = exporter._transform_to_dataset_item(trace)
        
        # Each score should have name and value
        for score in dataset_item["metadata"]["scores"]:
            assert "name" in score
            assert "value" in score


# =============================================================================
# Property 13: Ground Truth Candidate Handling
# =============================================================================

class TestProperty13GroundTruthCandidateHandling:
    """
    Feature: langfuse-evaluation-integration, Property 13: Ground Truth Candidate Handling
    
    *For any* trace where is_ground_truth_candidate=true, the transformed dataset item
    SHALL include evaluation_criteria in metadata.
    
    **Validates: Requirements 7.2**
    """
    
    @settings(max_examples=100)
    @given(trace=ground_truth_trace_strategy)
    def test_ground_truth_includes_evaluation_criteria(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 13: Ground truth candidate handling
        
        Test that ground truth candidates include evaluation_criteria in metadata.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        dataset_item = exporter._transform_to_dataset_item(trace)
        
        # evaluation_criteria should be included in metadata
        assert "evaluation_criteria" in dataset_item["metadata"]
        assert dataset_item["metadata"]["evaluation_criteria"] == trace["metadata"]["evaluation_criteria"]
    
    @settings(max_examples=100)
    @given(trace=ground_truth_trace_strategy)
    def test_ground_truth_flag_is_true(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 13: Ground truth candidate handling
        
        Test that is_ground_truth_candidate is True for ground truth traces.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        dataset_item = exporter._transform_to_dataset_item(trace)
        
        # is_ground_truth_candidate should be True
        assert dataset_item["metadata"]["is_ground_truth_candidate"] is True
    
    @settings(max_examples=100)
    @given(trace=ground_truth_trace_strategy)
    def test_ground_truth_preserves_all_data(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 13: Ground truth candidate handling
        
        Test that ground truth traces preserve all data like regular traces.
        
        **Validates: Requirements 7.2, 7.5**
        """
        exporter = create_disabled_exporter()
        
        dataset_item = exporter._transform_to_dataset_item(trace)
        
        # All key fields should be preserved
        assert dataset_item["input"] == trace["input"]
        assert dataset_item["expected_output"] == trace["output"]
        assert dataset_item["metadata"]["langfuse_trace_id"] == trace["id"]
        assert dataset_item["metadata"]["trace_type"] == trace["metadata"]["trace_type"]


# =============================================================================
# Combined Property Tests
# =============================================================================

class TestExportTransformationCombined:
    """
    Combined tests for export transformation properties.
    
    These tests verify the interaction between regular and ground truth exports.
    
    **Validates: Requirements 7.2, 7.5**
    """
    
    @settings(max_examples=100)
    @given(
        regular_trace=langfuse_trace_strategy,
        gt_trace=ground_truth_trace_strategy,
    )
    def test_regular_and_gt_traces_have_same_structure(
        self,
        regular_trace: Dict[str, Any],
        gt_trace: Dict[str, Any],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 11, 12, 13: Combined export validation
        
        Test that regular traces and ground truth traces have the same structure.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        regular_item = exporter._transform_to_dataset_item(regular_trace)
        gt_item = exporter._transform_to_dataset_item(gt_trace)
        
        # Both should have the same top-level keys
        assert set(regular_item.keys()) == set(gt_item.keys())
        assert "input" in regular_item
        assert "expected_output" in regular_item
        assert "metadata" in regular_item
    
    @settings(max_examples=100)
    @given(trace=langfuse_trace_strategy)
    def test_transformation_is_deterministic(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 11: Dataset item transformation preserves data
        
        Test that transformation produces consistent results for the same input.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        # Transform the same trace twice
        result1 = exporter._transform_to_dataset_item(trace)
        result2 = exporter._transform_to_dataset_item(trace)
        
        # Results should be identical for key fields
        assert result1["input"] == result2["input"]
        assert result1["expected_output"] == result2["expected_output"]
        assert result1["metadata"]["langfuse_trace_id"] == result2["metadata"]["langfuse_trace_id"]
        assert result1["metadata"]["trace_type"] == result2["metadata"]["trace_type"]
        assert result1["metadata"]["session_id"] == result2["metadata"]["session_id"]
    
    @settings(max_examples=100)
    @given(trace=ground_truth_trace_strategy)
    def test_gt_transformation_is_deterministic(self, trace: Dict[str, Any]):
        """
        Feature: langfuse-evaluation-integration, Property 13: Ground truth candidate handling
        
        Test that ground truth transformation produces consistent results.
        
        **Validates: Requirements 7.2**
        """
        exporter = create_disabled_exporter()
        
        # Transform the same trace twice
        result1 = exporter._transform_to_dataset_item(trace)
        result2 = exporter._transform_to_dataset_item(trace)
        
        # Results should be identical for key fields
        assert result1["input"] == result2["input"]
        assert result1["expected_output"] == result2["expected_output"]
        assert result1["metadata"]["langfuse_trace_id"] == result2["metadata"]["langfuse_trace_id"]
        assert result1["metadata"]["evaluation_criteria"] == result2["metadata"]["evaluation_criteria"]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])
