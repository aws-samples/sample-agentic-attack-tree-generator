#!/usr/bin/env python3
"""
Property-Based Tests for Phase Coverage Calculation

This module contains property-based tests using Hypothesis to validate
the correctness properties of phase coverage calculation in the ThreatForest
tracing module.

Properties tested:
- Property 10: Phase Coverage Calculation

**Validates: Requirements 5.4**

Requirements:
- 5.4: THE Tracing_Module SHALL calculate phase_coverage_score based on
       detected attack phases
"""

import sys
from pathlib import Path
from typing import Set, Dict, List

import pytest
from hypothesis import given, settings, strategies as st, assume

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from threatforest.tracing.metrics import (
    ATTACK_PHASES,
    PHASE_KEYWORDS,
    calculate_phase_coverage,
)


# =============================================================================
# Unique Keywords Mapping
# =============================================================================
# To properly test the phase coverage calculation, we need keywords that
# uniquely identify each phase without triggering other phases.
# This is necessary because some keywords in PHASE_KEYWORDS overlap
# (e.g., "discovery" triggers both "reconnaissance" and "discovery").

UNIQUE_PHASE_KEYWORDS: Dict[str, str] = {
    "reconnaissance": "reconnaissance",  # Unique to reconnaissance
    "initial_access": "initial_access",  # Unique underscore form
    "execution": "execution",  # Unique to execution
    "persistence": "persistence",  # Unique to persistence
    "privilege_escalation": "privilege_escalation",  # Unique underscore form
    "defense_evasion": "defense_evasion",  # Unique underscore form
    "credential_access": "credential_access",  # Unique underscore form
    "discovery": "account discovery",  # More specific to avoid overlap with recon
    "lateral_movement": "lateral_movement",  # Unique underscore form
    "collection": "collection",  # Unique to collection
    "exfiltration": "exfiltration",  # Unique to exfiltration
    "impact": "impact",  # Unique to impact
}


# =============================================================================
# Hypothesis Strategies for generating test data
# =============================================================================

# Strategy for generating sets of detected phases from ATTACK_PHASES
detected_phases_strategy = st.sets(
    st.sampled_from(sorted(list(ATTACK_PHASES))),
    min_size=0,
    max_size=len(ATTACK_PHASES)
)

# Strategy for generating non-empty sets of expected phases from ATTACK_PHASES
expected_phases_strategy = st.sets(
    st.sampled_from(sorted(list(ATTACK_PHASES))),
    min_size=1,
    max_size=len(ATTACK_PHASES)
)


# =============================================================================
# Helper Functions
# =============================================================================

def build_content_with_unique_phases(phases: Set[str]) -> str:
    """
    Build attack tree content that contains ONLY the specified phases.
    
    This function creates content using unique keywords that will trigger
    only the intended phases without cross-triggering other phases.
    
    Args:
        phases: Set of phase names to include in the content
        
    Returns:
        String content containing unique keywords for the specified phases
    """
    if not phases:
        return "# Empty Attack Tree\n- No phases detected"
    
    content_lines = ["# Attack Tree with Phases"]
    
    for phase in sorted(phases):
        if phase in UNIQUE_PHASE_KEYWORDS:
            keyword = UNIQUE_PHASE_KEYWORDS[phase]
            content_lines.append(f"## {keyword.title()}")
            content_lines.append(f"- Perform {keyword} activities")
    
    return "\n".join(content_lines)


def calculate_expected_coverage(detected: Set[str], expected: Set[str]) -> float:
    """
    Calculate the expected coverage score using the formula from the spec.
    
    The coverage score is calculated as:
        coverage_score = len(detected ∩ expected) / len(expected)
    
    Args:
        detected: Set of detected phases
        expected: Set of expected phases
        
    Returns:
        Coverage score as a float in range [0.0, 1.0]
    """
    if not expected:
        return 0.0
    
    intersection = detected & expected
    return len(intersection) / len(expected)


# =============================================================================
# Property 10: Phase Coverage Calculation
# =============================================================================

class TestProperty10PhaseCoverageCalculation:
    """
    Feature: langfuse-evaluation-integration, Property 10: Phase Coverage Calculation
    
    *For any* attack tree with detected phases P from the set of expected phases E,
    the `phase_coverage_score` SHALL equal `len(P ∩ E) / len(E)`.
    
    **Validates: Requirements 5.4**
    """
    
    @given(
        detected_phases=detected_phases_strategy,
        expected_phases=expected_phases_strategy,
    )
    @settings(max_examples=100)
    def test_phase_coverage_equals_intersection_over_expected(
        self,
        detected_phases: Set[str],
        expected_phases: Set[str],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 10: Phase coverage calculation
        
        Test that coverage_score = len(detected ∩ expected) / len(expected)
        for any combination of detected and expected phases.
        
        **Validates: Requirements 5.4**
        """
        # Build content that contains ONLY the detected phases using unique keywords
        content = build_content_with_unique_phases(detected_phases)
        
        # Calculate phase coverage using the function under test
        result = calculate_phase_coverage(content, expected_phases)
        
        # The actual detected phases from the result
        actual_detected = set(result["phases_detected"])
        
        # Calculate expected coverage using the formula from the spec
        # coverage_score = len(detected ∩ expected) / len(expected)
        expected_coverage = calculate_expected_coverage(actual_detected, expected_phases)
        
        # Verify the coverage score matches the formula
        # Use a small tolerance for floating point comparison
        assert abs(result["coverage_score"] - expected_coverage) < 0.0001, (
            f"Coverage mismatch: got {result['coverage_score']}, "
            f"expected {expected_coverage} for detected={actual_detected}, "
            f"expected_phases={expected_phases}"
        )
    
    @given(
        expected_phases=expected_phases_strategy,
    )
    @settings(max_examples=100)
    def test_empty_detected_phases_gives_zero_coverage(
        self,
        expected_phases: Set[str],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 10: Phase coverage calculation
        
        Test that when no phases are detected, coverage is 0.0.
        
        **Validates: Requirements 5.4**
        """
        # Content with no phase keywords
        content = "# Generic Attack Tree\n- Some generic step"
        
        result = calculate_phase_coverage(content, expected_phases)
        
        # With no detected phases, coverage should be 0.0
        assert result["coverage_score"] == 0.0
    
    @given(
        phases=expected_phases_strategy,
    )
    @settings(max_examples=100)
    def test_all_expected_phases_detected_gives_full_coverage(
        self,
        phases: Set[str],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 10: Phase coverage calculation
        
        Test that when all expected phases are detected, coverage is 1.0.
        
        **Validates: Requirements 5.4**
        """
        # Build content with all expected phases using unique keywords
        content = build_content_with_unique_phases(phases)
        
        result = calculate_phase_coverage(content, phases)
        
        # All expected phases detected means full coverage
        assert result["coverage_score"] == 1.0
    
    @given(
        detected_phases=detected_phases_strategy,
        expected_phases=expected_phases_strategy,
    )
    @settings(max_examples=100)
    def test_coverage_score_is_in_valid_range(
        self,
        detected_phases: Set[str],
        expected_phases: Set[str],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 10: Phase coverage calculation
        
        Test that coverage score is always in range [0.0, 1.0].
        
        **Validates: Requirements 5.4**
        """
        content = build_content_with_unique_phases(detected_phases)
        
        result = calculate_phase_coverage(content, expected_phases)
        
        assert 0.0 <= result["coverage_score"] <= 1.0
    
    @given(
        detected_phases=detected_phases_strategy,
        expected_phases=expected_phases_strategy,
    )
    @settings(max_examples=100)
    def test_detected_phases_are_subset_of_attack_phases(
        self,
        detected_phases: Set[str],
        expected_phases: Set[str],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 10: Phase coverage calculation
        
        Test that detected phases are always from the valid ATTACK_PHASES set.
        
        **Validates: Requirements 5.4**
        """
        content = build_content_with_unique_phases(detected_phases)
        
        result = calculate_phase_coverage(content, expected_phases)
        
        # All detected phases should be valid attack phases
        detected_set = set(result["phases_detected"])
        assert detected_set.issubset(ATTACK_PHASES)
    
    @given(
        detected_phases=detected_phases_strategy,
        expected_phases=expected_phases_strategy,
    )
    @settings(max_examples=100)
    def test_intersection_property_holds(
        self,
        detected_phases: Set[str],
        expected_phases: Set[str],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 10: Phase coverage calculation
        
        Test that the intersection of detected and expected phases
        determines the coverage score.
        
        **Validates: Requirements 5.4**
        """
        content = build_content_with_unique_phases(detected_phases)
        
        result = calculate_phase_coverage(content, expected_phases)
        
        # Calculate intersection using actual detected phases
        detected_set = set(result["phases_detected"])
        intersection = detected_set & expected_phases
        
        # Coverage should equal intersection size / expected size
        expected_coverage = len(intersection) / len(expected_phases)
        
        assert abs(result["coverage_score"] - expected_coverage) < 0.0001
    
    @given(
        subset_phases=expected_phases_strategy,
    )
    @settings(max_examples=100)
    def test_partial_coverage_calculation(
        self,
        subset_phases: Set[str],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 10: Phase coverage calculation
        
        Test partial coverage when only some expected phases are detected.
        
        **Validates: Requirements 5.4**
        """
        # Ensure we have at least 2 phases to test partial coverage
        assume(len(subset_phases) >= 2)
        
        # Take half of the phases as detected
        phases_list = sorted(list(subset_phases))
        half_count = len(phases_list) // 2
        detected_phases = set(phases_list[:half_count])
        
        content = build_content_with_unique_phases(detected_phases)
        
        result = calculate_phase_coverage(content, subset_phases)
        
        # Get actual detected phases from result
        actual_detected = set(result["phases_detected"])
        
        # Coverage should be intersection / expected
        intersection = actual_detected & subset_phases
        expected_coverage = len(intersection) / len(subset_phases)
        
        assert abs(result["coverage_score"] - expected_coverage) < 0.0001
    
    @given(
        detected_phases=detected_phases_strategy,
        expected_phases=expected_phases_strategy,
    )
    @settings(max_examples=100)
    def test_coverage_monotonicity_with_more_detected_phases(
        self,
        detected_phases: Set[str],
        expected_phases: Set[str],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 10: Phase coverage calculation
        
        Test that adding more detected phases (that are in expected) 
        increases or maintains coverage.
        
        **Validates: Requirements 5.4**
        """
        # Calculate coverage with original detected phases
        content1 = build_content_with_unique_phases(detected_phases)
        result1 = calculate_phase_coverage(content1, expected_phases)
        
        # Add one more phase from expected (if possible)
        additional_phases = expected_phases - detected_phases
        if additional_phases:
            new_detected = detected_phases | {next(iter(additional_phases))}
            content2 = build_content_with_unique_phases(new_detected)
            result2 = calculate_phase_coverage(content2, expected_phases)
            
            # Coverage should increase or stay the same
            assert result2["coverage_score"] >= result1["coverage_score"]
    
    @given(
        phases=expected_phases_strategy,
    )
    @settings(max_examples=100)
    def test_coverage_with_superset_detected_equals_full_coverage(
        self,
        phases: Set[str],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 10: Phase coverage calculation
        
        Test that detecting more phases than expected still gives 1.0 coverage.
        
        **Validates: Requirements 5.4**
        """
        # Detect all ATTACK_PHASES (superset of any expected subset)
        content = build_content_with_unique_phases(ATTACK_PHASES)
        
        result = calculate_phase_coverage(content, phases)
        
        # Coverage should be 1.0 since all expected phases are detected
        assert result["coverage_score"] == 1.0
    
    @given(
        detected_phases=detected_phases_strategy,
        expected_phases=expected_phases_strategy,
    )
    @settings(max_examples=100)
    def test_disjoint_phases_give_zero_coverage(
        self,
        detected_phases: Set[str],
        expected_phases: Set[str],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 10: Phase coverage calculation
        
        Test that when detected and expected phases are disjoint, coverage is 0.0.
        
        **Validates: Requirements 5.4**
        """
        # Only test when sets are actually disjoint
        assume(detected_phases.isdisjoint(expected_phases))
        
        content = build_content_with_unique_phases(detected_phases)
        
        result = calculate_phase_coverage(content, expected_phases)
        
        # Get actual detected phases
        actual_detected = set(result["phases_detected"])
        
        # Verify the formula: if actual detected is disjoint from expected, coverage is 0
        if actual_detected.isdisjoint(expected_phases):
            assert result["coverage_score"] == 0.0
        else:
            # If there's overlap due to keyword detection, verify the formula still holds
            intersection = actual_detected & expected_phases
            expected_coverage = len(intersection) / len(expected_phases)
            assert abs(result["coverage_score"] - expected_coverage) < 0.0001


# =============================================================================
# Additional Edge Case Tests
# =============================================================================

class TestPhaseCoverageEdgeCases:
    """
    Edge case tests for phase coverage calculation.
    
    **Validates: Requirements 5.4**
    """
    
    def test_single_phase_detected_single_expected(self):
        """
        Feature: langfuse-evaluation-integration, Property 10: Phase coverage calculation
        
        Test coverage with single phase detected and single expected.
        
        **Validates: Requirements 5.4**
        """
        expected = {"reconnaissance"}
        content = build_content_with_unique_phases({"reconnaissance"})
        
        result = calculate_phase_coverage(content, expected)
        
        assert result["coverage_score"] == 1.0
        assert "reconnaissance" in result["phases_detected"]
    
    def test_all_twelve_phases_detected(self):
        """
        Feature: langfuse-evaluation-integration, Property 10: Phase coverage calculation
        
        Test coverage when all 12 MITRE ATT&CK phases are detected.
        
        **Validates: Requirements 5.4**
        """
        content = build_content_with_unique_phases(ATTACK_PHASES)
        
        result = calculate_phase_coverage(content, ATTACK_PHASES)
        
        assert result["coverage_score"] == 1.0
        assert len(result["phases_detected"]) == 12
    
    def test_coverage_with_default_expected_phases(self):
        """
        Feature: langfuse-evaluation-integration, Property 10: Phase coverage calculation
        
        Test that default expected phases is ATTACK_PHASES.
        
        **Validates: Requirements 5.4**
        """
        content = build_content_with_unique_phases({"reconnaissance", "execution"})
        
        result = calculate_phase_coverage(content)  # No expected_phases argument
        
        # Default expected is all 12 phases
        assert set(result["expected_phases"]) == ATTACK_PHASES
        # 2 out of 12 phases detected
        expected_coverage = 2 / 12
        assert abs(result["coverage_score"] - expected_coverage) < 0.0001
    
    @given(
        expected_phases=expected_phases_strategy,
    )
    @settings(max_examples=100)
    def test_empty_content_gives_zero_coverage(
        self,
        expected_phases: Set[str],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 10: Phase coverage calculation
        
        Test that empty content gives zero coverage.
        
        **Validates: Requirements 5.4**
        """
        result = calculate_phase_coverage("", expected_phases)
        
        assert result["coverage_score"] == 0.0
        assert len(result["phases_detected"]) == 0
    
    @given(
        expected_phases=expected_phases_strategy,
    )
    @settings(max_examples=100)
    def test_whitespace_content_gives_zero_coverage(
        self,
        expected_phases: Set[str],
    ):
        """
        Feature: langfuse-evaluation-integration, Property 10: Phase coverage calculation
        
        Test that whitespace-only content gives zero coverage.
        
        **Validates: Requirements 5.4**
        """
        result = calculate_phase_coverage("   \n\t\n   ", expected_phases)
        
        assert result["coverage_score"] == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])
