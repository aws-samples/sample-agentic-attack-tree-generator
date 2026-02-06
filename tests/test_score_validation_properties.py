#!/usr/bin/env python3
"""
Property-Based Tests for Score Validation

This module contains property-based tests using Hypothesis to validate
the correctness properties of score validation in the Langfuse tracing module.

Properties tested:
- Property 8: Score Values in Valid Range
- Property 9: Categorical TTP Score Mapping

**Validates: Requirements 4.2, 6.1**

Requirements:
- 4.2: THE Tracing_Module SHALL support scores as float values in range 0.0 to 1.0
- 6.1: THE Tracing_Module SHALL register score definitions for TTP mappings with
       categorical values: excellent (1.0), good (0.66), poor (0.33), no_mapping (0.0)
"""

import sys
from pathlib import Path
from typing import List
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings, strategies as st, assume

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from threatforest.tracing.manager import LangfuseTrace
from threatforest.tracing.noop import NoOpTrace
from threatforest.tracing.scores import (
    TTP_SCORE_VALUES,
    TTP_MAPPING_SCORES,
    get_ttp_numeric_value,
)


# =============================================================================
# Hypothesis Strategies for generating test data
# =============================================================================

# Strategy for generating valid score values in range [0.0, 1.0]
valid_score_strategy = st.floats(
    min_value=0.0,
    max_value=1.0,
    allow_nan=False,
    allow_infinity=False
)

# Strategy for generating invalid score values (outside range [0.0, 1.0])
invalid_score_strategy = st.one_of(
    # Values below 0.0
    st.floats(
        max_value=-0.0001,
        allow_nan=False,
        allow_infinity=False
    ).filter(lambda x: x < 0.0),
    # Values above 1.0
    st.floats(
        min_value=1.0001,
        allow_nan=False,
        allow_infinity=False
    ).filter(lambda x: x > 1.0)
)

# Strategy for generating score names
score_name_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=50
).filter(lambda s: s.strip() != "")

# Strategy for generating optional comments
comment_strategy = st.one_of(
    st.none(),
    st.text(
        alphabet=st.characters(whitelist_categories=("L", "N", "P", "S")),
        min_size=1,
        max_size=200
    ).filter(lambda s: s.strip() != "")
)

# Strategy for generating TTP categories (now 5 categories)
ttp_category_strategy = st.sampled_from(["excellent", "good", "acceptable", "poor", "no_mapping"])

# Strategy for generating invalid TTP categories
invalid_ttp_category_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=50
).filter(lambda s: s not in TTP_SCORE_VALUES and s.strip() != "")


# =============================================================================
# Helper function to create a LangfuseTrace with mocked Langfuse
# =============================================================================

def create_mocked_langfuse_trace(session_id: str = "test-session") -> LangfuseTrace:
    """
    Create a LangfuseTrace with a mocked Langfuse trace object.
    
    Returns:
        LangfuseTrace: A trace with mocked underlying Langfuse trace.
    """
    mock_langfuse_trace = MagicMock()
    
    return LangfuseTrace(
        langfuse_trace=mock_langfuse_trace,
        trace_id="test-trace-id",
        session_id=session_id,
    )


# =============================================================================
# Property 8: Score Values in Valid Range
# =============================================================================

class TestProperty8ScoreValuesInValidRange:
    """
    Feature: langfuse-evaluation-integration, Property 8: Score Values in Valid Range
    
    *For any* numeric score added to a trace, the value SHALL be a float in the
    range [0.0, 1.0]. Values outside this range SHALL be rejected.
    
    **Validates: Requirements 4.2**
    """
    
    @settings(max_examples=100)
    @given(
        score_value=valid_score_strategy,
        score_name=score_name_strategy,
        comment=comment_strategy,
    )
    def test_valid_scores_in_range_are_accepted(
        self,
        score_value: float,
        score_name: str,
        comment: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 8: Score Values in Valid Range
        
        Test that valid scores in range [0.0, 1.0] are accepted without raising errors.
        
        **Validates: Requirements 4.2**
        """
        trace = create_mocked_langfuse_trace()
        
        # Should not raise any exception
        trace.add_score(score_name, score_value, comment)
        
        # Verify the score was passed to the underlying Langfuse trace
        trace._langfuse_trace.score.assert_called_once()
        call_kwargs = trace._langfuse_trace.score.call_args[1]
        assert call_kwargs["name"] == score_name
        assert call_kwargs["value"] == score_value
    
    @settings(max_examples=100)
    @given(
        score_value=invalid_score_strategy,
        score_name=score_name_strategy,
        comment=comment_strategy,
    )
    def test_invalid_scores_outside_range_are_rejected(
        self,
        score_value: float,
        score_name: str,
        comment: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 8: Score Values in Valid Range
        
        Test that invalid scores outside range [0.0, 1.0] are rejected with ValueError.
        
        **Validates: Requirements 4.2**
        """
        trace = create_mocked_langfuse_trace()
        
        # Should raise ValueError for out-of-range scores
        with pytest.raises(ValueError, match=r"Score value must be in range \[0\.0, 1\.0\]"):
            trace.add_score(score_name, score_value, comment)
        
        # Verify the score was NOT passed to the underlying Langfuse trace
        trace._langfuse_trace.score.assert_not_called()
    
    @settings(max_examples=100)
    @given(
        score_name=score_name_strategy,
    )
    def test_boundary_value_zero_is_accepted(
        self,
        score_name: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 8: Score Values in Valid Range
        
        Test that the boundary value 0.0 is accepted.
        
        **Validates: Requirements 4.2**
        """
        trace = create_mocked_langfuse_trace()
        
        # Should not raise any exception
        trace.add_score(score_name, 0.0)
        
        # Verify the score was passed correctly
        call_kwargs = trace._langfuse_trace.score.call_args[1]
        assert call_kwargs["value"] == 0.0
    
    @settings(max_examples=100)
    @given(
        score_name=score_name_strategy,
    )
    def test_boundary_value_one_is_accepted(
        self,
        score_name: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 8: Score Values in Valid Range
        
        Test that the boundary value 1.0 is accepted.
        
        **Validates: Requirements 4.2**
        """
        trace = create_mocked_langfuse_trace()
        
        # Should not raise any exception
        trace.add_score(score_name, 1.0)
        
        # Verify the score was passed correctly
        call_kwargs = trace._langfuse_trace.score.call_args[1]
        assert call_kwargs["value"] == 1.0
    
    @settings(max_examples=100)
    @given(
        score_name=score_name_strategy,
    )
    def test_value_just_below_zero_is_rejected(
        self,
        score_name: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 8: Score Values in Valid Range
        
        Test that values just below 0.0 are rejected.
        
        **Validates: Requirements 4.2**
        """
        trace = create_mocked_langfuse_trace()
        
        # Should raise ValueError
        with pytest.raises(ValueError, match=r"Score value must be in range \[0\.0, 1\.0\]"):
            trace.add_score(score_name, -0.0001)
    
    @settings(max_examples=100)
    @given(
        score_name=score_name_strategy,
    )
    def test_value_just_above_one_is_rejected(
        self,
        score_name: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 8: Score Values in Valid Range
        
        Test that values just above 1.0 are rejected.
        
        **Validates: Requirements 4.2**
        """
        trace = create_mocked_langfuse_trace()
        
        # Should raise ValueError
        with pytest.raises(ValueError, match=r"Score value must be in range \[0\.0, 1\.0\]"):
            trace.add_score(score_name, 1.0001)
    
    @settings(max_examples=100)
    @given(
        score_value=valid_score_strategy,
        score_name=score_name_strategy,
    )
    def test_noop_trace_accepts_valid_scores_without_error(
        self,
        score_value: float,
        score_name: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 8: Score Values in Valid Range
        
        Test that NoOpTrace accepts valid scores without raising errors.
        
        **Validates: Requirements 4.2**
        """
        trace = NoOpTrace()
        
        # Should not raise any exception
        trace.add_score(score_name, score_value)
    
    @settings(max_examples=100)
    @given(
        score_value=valid_score_strategy,
        score_name=score_name_strategy,
        comment=st.text(min_size=1, max_size=100).filter(lambda s: s.strip() != ""),
    )
    def test_score_with_comment_is_passed_correctly(
        self,
        score_value: float,
        score_name: str,
        comment: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 8: Score Values in Valid Range
        
        Test that scores with comments are passed correctly to Langfuse.
        
        **Validates: Requirements 4.2**
        """
        trace = create_mocked_langfuse_trace()
        
        trace.add_score(score_name, score_value, comment)
        
        # Verify the comment was passed
        call_kwargs = trace._langfuse_trace.score.call_args[1]
        assert call_kwargs["comment"] == comment
    
    @settings(max_examples=100)
    @given(
        score_value=valid_score_strategy,
        score_name=score_name_strategy,
    )
    def test_score_without_comment_does_not_include_comment_key(
        self,
        score_value: float,
        score_name: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 8: Score Values in Valid Range
        
        Test that scores without comments do not include the comment key.
        
        **Validates: Requirements 4.2**
        """
        trace = create_mocked_langfuse_trace()
        
        trace.add_score(score_name, score_value, None)
        
        # Verify comment key is not present
        call_kwargs = trace._langfuse_trace.score.call_args[1]
        assert "comment" not in call_kwargs


# =============================================================================
# Property 9: Categorical TTP Score Mapping
# =============================================================================

class TestProperty9CategoricalTTPScoreMapping:
    """
    Feature: langfuse-evaluation-integration, Property 9: Categorical TTP Score Mapping
    
    *For any* TTP mapping score with category in {excellent, good, poor, no_mapping},
    the numeric value SHALL be {1.0, 0.66, 0.33, 0.0} respectively.
    
    **Validates: Requirements 6.1**
    """
    
    @settings(max_examples=100)
    @given(
        category=ttp_category_strategy,
    )
    def test_ttp_category_maps_to_correct_numeric_value(
        self,
        category: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 9: Categorical TTP Score Mapping
        
        Test that each TTP category maps to the correct numeric value.
        
        **Validates: Requirements 6.1**
        """
        expected_values = {
            "excellent": 1.0,
            "good": 0.75,
            "acceptable": 0.5,
            "poor": 0.25,
            "no_mapping": 0.0
        }
        
        # Verify the mapping is correct
        assert TTP_SCORE_VALUES[category] == expected_values[category]
        
        # Also verify via the helper function
        assert get_ttp_numeric_value(category) == expected_values[category]
    
    def test_excellent_maps_to_one(self):
        """
        Feature: langfuse-evaluation-integration, Property 9: Categorical TTP Score Mapping
        
        Test that 'excellent' category maps to 1.0.
        
        **Validates: Requirements 6.1**
        """
        assert TTP_SCORE_VALUES["excellent"] == 1.0
        assert get_ttp_numeric_value("excellent") == 1.0
    
    def test_good_maps_to_075(self):
        """
        Feature: langfuse-evaluation-integration, Property 9: Categorical TTP Score Mapping
        
        Test that 'good' category maps to 0.75.
        
        **Validates: Requirements 6.1**
        """
        assert TTP_SCORE_VALUES["good"] == 0.75
        assert get_ttp_numeric_value("good") == 0.75
    
    def test_acceptable_maps_to_05(self):
        """
        Feature: langfuse-evaluation-integration, Property 9: Categorical TTP Score Mapping
        
        Test that 'acceptable' category maps to 0.5.
        
        **Validates: Requirements 6.1**
        """
        assert TTP_SCORE_VALUES["acceptable"] == 0.5
        assert get_ttp_numeric_value("acceptable") == 0.5
    
    def test_poor_maps_to_025(self):
        """
        Feature: langfuse-evaluation-integration, Property 9: Categorical TTP Score Mapping
        
        Test that 'poor' category maps to 0.25.
        
        **Validates: Requirements 6.1**
        """
        assert TTP_SCORE_VALUES["poor"] == 0.25
        assert get_ttp_numeric_value("poor") == 0.25
    
    def test_no_mapping_maps_to_zero(self):
        """
        Feature: langfuse-evaluation-integration, Property 9: Categorical TTP Score Mapping
        
        Test that 'no_mapping' category maps to 0.0.
        
        **Validates: Requirements 6.1**
        """
        assert TTP_SCORE_VALUES["no_mapping"] == 0.0
        assert get_ttp_numeric_value("no_mapping") == 0.0
    
    @settings(max_examples=100)
    @given(
        category=ttp_category_strategy,
    )
    def test_ttp_mapping_is_consistent_across_calls(
        self,
        category: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 9: Categorical TTP Score Mapping
        
        Test that the TTP mapping is consistent across multiple calls.
        
        **Validates: Requirements 6.1**
        """
        # Call multiple times and verify consistency
        value1 = TTP_SCORE_VALUES[category]
        value2 = TTP_SCORE_VALUES[category]
        value3 = get_ttp_numeric_value(category)
        
        assert value1 == value2 == value3
    
    @settings(max_examples=100)
    @given(
        invalid_category=invalid_ttp_category_strategy,
    )
    def test_invalid_ttp_category_raises_error(
        self,
        invalid_category: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 9: Categorical TTP Score Mapping
        
        Test that invalid TTP categories raise ValueError.
        
        **Validates: Requirements 6.1**
        """
        # Verify invalid category is not in the mapping
        assert invalid_category not in TTP_SCORE_VALUES
        
        # Verify get_ttp_numeric_value raises ValueError
        with pytest.raises(ValueError, match="Invalid TTP category"):
            get_ttp_numeric_value(invalid_category)
    
    @settings(max_examples=100)
    @given(
        category=ttp_category_strategy,
    )
    def test_ttp_score_values_are_in_valid_range(
        self,
        category: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 9: Categorical TTP Score Mapping
        
        Test that all TTP score values are in the valid range [0.0, 1.0].
        
        **Validates: Requirements 6.1**
        """
        value = TTP_SCORE_VALUES[category]
        
        assert 0.0 <= value <= 1.0
    
    def test_ttp_score_values_are_ordered_by_quality(self):
        """
        Feature: langfuse-evaluation-integration, Property 9: Categorical TTP Score Mapping
        
        Test that TTP score values are ordered by quality (excellent > good > acceptable > poor > no_mapping).
        
        **Validates: Requirements 6.1**
        """
        assert TTP_SCORE_VALUES["excellent"] > TTP_SCORE_VALUES["good"]
        assert TTP_SCORE_VALUES["good"] > TTP_SCORE_VALUES["acceptable"]
        assert TTP_SCORE_VALUES["acceptable"] > TTP_SCORE_VALUES["poor"]
        assert TTP_SCORE_VALUES["poor"] > TTP_SCORE_VALUES["no_mapping"]
    
    def test_ttp_mapping_scores_definition_has_correct_categories(self):
        """
        Feature: langfuse-evaluation-integration, Property 9: Categorical TTP Score Mapping
        
        Test that TTP_MAPPING_SCORES definition has the correct categories.
        
        **Validates: Requirements 6.1**
        """
        mapping_quality_score = TTP_MAPPING_SCORES[0]
        
        assert mapping_quality_score.name == "mapping_quality"
        assert set(mapping_quality_score.categories) == {"excellent", "good", "acceptable", "poor", "no_mapping"}
    
    @settings(max_examples=100)
    @given(
        category=ttp_category_strategy,
        score_name=score_name_strategy,
        comment=comment_strategy,
    )
    def test_categorical_score_can_be_added_to_trace(
        self,
        category: str,
        score_name: str,
        comment: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 9: Categorical TTP Score Mapping
        
        Test that categorical TTP scores can be added to a trace.
        
        **Validates: Requirements 6.1**
        """
        trace = create_mocked_langfuse_trace()
        allowed_categories = list(TTP_SCORE_VALUES.keys())
        
        # Should not raise any exception
        trace.add_categorical_score(score_name, category, allowed_categories, comment)
        
        # Verify the score was passed to the underlying Langfuse trace
        trace._langfuse_trace.score.assert_called_once()
        call_kwargs = trace._langfuse_trace.score.call_args[1]
        assert call_kwargs["name"] == score_name
        assert call_kwargs["value"] == category
    
    @settings(max_examples=100)
    @given(
        invalid_category=invalid_ttp_category_strategy,
        score_name=score_name_strategy,
    )
    def test_invalid_categorical_score_is_rejected(
        self,
        invalid_category: str,
        score_name: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 9: Categorical TTP Score Mapping
        
        Test that invalid categorical scores are rejected.
        
        **Validates: Requirements 6.1**
        """
        trace = create_mocked_langfuse_trace()
        allowed_categories = list(TTP_SCORE_VALUES.keys())
        
        # Should raise ValueError for invalid category
        with pytest.raises(ValueError, match="not in allowed categories"):
            trace.add_categorical_score(score_name, invalid_category, allowed_categories)
        
        # Verify the score was NOT passed to the underlying Langfuse trace
        trace._langfuse_trace.score.assert_not_called()


# =============================================================================
# Combined Property Tests
# =============================================================================

class TestScoreValidationCombined:
    """
    Combined tests for score validation properties.
    
    These tests verify the interaction between numeric and categorical scores.
    
    **Validates: Requirements 4.2, 6.1**
    """
    
    @settings(max_examples=100)
    @given(
        numeric_score=valid_score_strategy,
        ttp_category=ttp_category_strategy,
        score_name=score_name_strategy,
    )
    def test_both_numeric_and_categorical_scores_can_be_added(
        self,
        numeric_score: float,
        ttp_category: str,
        score_name: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 8 & 9: Combined score validation
        
        Test that both numeric and categorical scores can be added to the same trace.
        
        **Validates: Requirements 4.2, 6.1**
        """
        trace = create_mocked_langfuse_trace()
        allowed_categories = list(TTP_SCORE_VALUES.keys())
        
        # Add numeric score
        trace.add_score(f"{score_name}_numeric", numeric_score)
        
        # Add categorical score
        trace.add_categorical_score(f"{score_name}_categorical", ttp_category, allowed_categories)
        
        # Verify both scores were added
        assert trace._langfuse_trace.score.call_count == 2
    
    @settings(max_examples=100)
    @given(
        ttp_category=ttp_category_strategy,
    )
    def test_ttp_numeric_value_is_valid_score(
        self,
        ttp_category: str,
    ):
        """
        Feature: langfuse-evaluation-integration, Property 8 & 9: Combined score validation
        
        Test that TTP numeric values are valid scores in range [0.0, 1.0].
        
        **Validates: Requirements 4.2, 6.1**
        """
        numeric_value = get_ttp_numeric_value(ttp_category)
        
        # The numeric value should be a valid score
        trace = create_mocked_langfuse_trace()
        
        # Should not raise any exception
        trace.add_score("ttp_numeric", numeric_value)
        
        # Verify the score was passed correctly
        call_kwargs = trace._langfuse_trace.score.call_args[1]
        assert call_kwargs["value"] == numeric_value


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])
