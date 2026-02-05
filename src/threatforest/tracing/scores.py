"""
Score Definitions for ThreatForest Tracing

This module defines the score dimensions used for evaluating ThreatForest outputs
across three core capabilities:
- Threat Statement Generation
- Attack Tree Generation
- TTP (Tactics, Techniques, and Procedures) Matching

Score definitions support both numeric scores (0.0-1.0 range) and categorical
scores with predefined categories.

Requirements:
- 4.1: Define score dimensions for threat statement evaluation
- 5.1: Define score dimensions for attack tree evaluation
- 6.1: Define categorical scores for TTP mapping quality
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class ScoreType(Enum):
    """
    Types of scores supported by the tracing system.
    
    Attributes:
        NUMERIC: Continuous scores in the range [0.0, 1.0]
        CATEGORICAL: Discrete scores from predefined categories
    """
    NUMERIC = "numeric"  # 0.0 - 1.0
    CATEGORICAL = "categorical"  # predefined categories


@dataclass
class ScoreDefinition:
    """
    Definition of a score dimension for evaluation.
    
    A score definition describes a single evaluation dimension that can be
    applied to traces or spans. It specifies the score type, valid range,
    and for categorical scores, the allowed categories.
    
    Attributes:
        name: Unique identifier for the score dimension
        score_type: Whether this is a numeric or categorical score
        description: Human-readable description of what this score measures
        categories: List of valid categories (only for CATEGORICAL scores)
        min_value: Minimum allowed value for numeric scores (default: 0.0)
        max_value: Maximum allowed value for numeric scores (default: 1.0)
    
    Example:
        >>> score = ScoreDefinition(
        ...     name="quality",
        ...     score_type=ScoreType.NUMERIC,
        ...     description="Overall quality rating"
        ... )
        >>> score.name
        'quality'
    """
    name: str
    score_type: ScoreType
    description: str
    categories: Optional[List[str]] = None  # For categorical scores
    min_value: float = 0.0
    max_value: float = 1.0
    
    def __post_init__(self) -> None:
        """Validate score definition after initialization."""
        if self.score_type == ScoreType.CATEGORICAL and not self.categories:
            raise ValueError(
                f"Score '{self.name}' is categorical but no categories provided"
            )
        if self.score_type == ScoreType.NUMERIC and self.categories:
            raise ValueError(
                f"Score '{self.name}' is numeric but categories were provided"
            )
        if self.min_value >= self.max_value:
            raise ValueError(
                f"Score '{self.name}' has invalid range: "
                f"min_value ({self.min_value}) must be less than max_value ({self.max_value})"
            )
    
    def validate_value(self, value: float) -> bool:
        """
        Validate that a score value is within the allowed range.
        
        Args:
            value: The score value to validate
            
        Returns:
            True if the value is valid
            
        Raises:
            ValueError: If the value is outside the allowed range
        """
        if self.score_type == ScoreType.NUMERIC:
            if not (self.min_value <= value <= self.max_value):
                raise ValueError(
                    f"Score '{self.name}' value {value} is outside range "
                    f"[{self.min_value}, {self.max_value}]"
                )
        return True
    
    def validate_category(self, category: str) -> bool:
        """
        Validate that a category is in the allowed list.
        
        Args:
            category: The category to validate
            
        Returns:
            True if the category is valid
            
        Raises:
            ValueError: If the category is not in the allowed list
        """
        if self.score_type == ScoreType.CATEGORICAL:
            if self.categories and category not in self.categories:
                raise ValueError(
                    f"Score '{self.name}' category '{category}' is not in "
                    f"allowed categories: {self.categories}"
                )
        return True


# =============================================================================
# Threat Statement Score Definitions
# =============================================================================
# These scores evaluate the quality of generated threat statements.
# Requirement 4.1: Define score dimensions for threat statement evaluation

THREAT_STATEMENT_SCORES: List[ScoreDefinition] = [
    ScoreDefinition(
        name="overall_quality",
        score_type=ScoreType.NUMERIC,
        description="Overall quality of generated threats"
    ),
    ScoreDefinition(
        name="relevance_to_context",
        score_type=ScoreType.NUMERIC,
        description="How well threats match application context"
    ),
    ScoreDefinition(
        name="completeness",
        score_type=ScoreType.NUMERIC,
        description="Coverage of threat categories"
    ),
    ScoreDefinition(
        name="technical_accuracy",
        score_type=ScoreType.NUMERIC,
        description="Technical correctness of threats"
    ),
    ScoreDefinition(
        name="hallucination_score",
        score_type=ScoreType.NUMERIC,
        description="1.0 = no hallucinations, 0.0 = all hallucinated"
    ),
]


# =============================================================================
# Attack Tree Score Definitions
# =============================================================================
# These scores evaluate the quality of generated attack trees.
# Requirement 5.1: Define score dimensions for attack tree evaluation

ATTACK_TREE_SCORES: List[ScoreDefinition] = [
    ScoreDefinition(
        name="overall_quality",
        score_type=ScoreType.NUMERIC,
        description="Overall quality of attack tree"
    ),
    ScoreDefinition(
        name="structural_quality",
        score_type=ScoreType.NUMERIC,
        description="Quality of tree structure"
    ),
    ScoreDefinition(
        name="technical_realism",
        score_type=ScoreType.NUMERIC,
        description="Realism of attack techniques"
    ),
    ScoreDefinition(
        name="attack_path_logic",
        score_type=ScoreType.NUMERIC,
        description="Logical progression of attack paths"
    ),
    ScoreDefinition(
        name="completeness",
        score_type=ScoreType.NUMERIC,
        description="Coverage of attack vectors"
    ),
    ScoreDefinition(
        name="actionability",
        score_type=ScoreType.NUMERIC,
        description="Usefulness for defenders"
    ),
]


# =============================================================================
# TTP Matching Score Definitions
# =============================================================================
# These scores evaluate the quality of TTP (MITRE ATT&CK) mappings.
# Requirement 6.1: Define categorical scores for TTP mapping quality

TTP_MAPPING_SCORES: List[ScoreDefinition] = [
    ScoreDefinition(
        name="mapping_quality",
        score_type=ScoreType.CATEGORICAL,
        description="Quality of technique mapping",
        categories=["excellent", "good", "poor", "no_mapping"]
    ),
]


# =============================================================================
# TTP Score Value Mapping
# =============================================================================
# Maps categorical TTP scores to numeric values for aggregation and analysis.
# Requirement 6.1: Define categorical scores for TTP mapping quality

TTP_SCORE_VALUES: dict[str, float] = {
    "excellent": 1.0,
    "good": 0.66,
    "poor": 0.33,
    "no_mapping": 0.0
}


# =============================================================================
# Helper Functions
# =============================================================================

def get_score_definition(
    name: str,
    score_list: List[ScoreDefinition]
) -> Optional[ScoreDefinition]:
    """
    Find a score definition by name in a list of definitions.
    
    Args:
        name: The name of the score to find
        score_list: List of score definitions to search
        
    Returns:
        The matching ScoreDefinition, or None if not found
        
    Example:
        >>> score = get_score_definition("overall_quality", THREAT_STATEMENT_SCORES)
        >>> score.description
        'Overall quality of generated threats'
    """
    for score in score_list:
        if score.name == name:
            return score
    return None


def get_ttp_numeric_value(category: str) -> float:
    """
    Convert a TTP categorical score to its numeric value.
    
    Args:
        category: The categorical score (excellent, good, poor, no_mapping)
        
    Returns:
        The corresponding numeric value
        
    Raises:
        ValueError: If the category is not valid
        
    Example:
        >>> get_ttp_numeric_value("excellent")
        1.0
        >>> get_ttp_numeric_value("good")
        0.66
    """
    if category not in TTP_SCORE_VALUES:
        raise ValueError(
            f"Invalid TTP category '{category}'. "
            f"Valid categories: {list(TTP_SCORE_VALUES.keys())}"
        )
    return TTP_SCORE_VALUES[category]


def get_all_score_definitions() -> List[ScoreDefinition]:
    """
    Get all score definitions across all capabilities.
    
    Returns:
        Combined list of all score definitions
        
    Example:
        >>> all_scores = get_all_score_definitions()
        >>> len(all_scores)
        12
    """
    return THREAT_STATEMENT_SCORES + ATTACK_TREE_SCORES + TTP_MAPPING_SCORES
