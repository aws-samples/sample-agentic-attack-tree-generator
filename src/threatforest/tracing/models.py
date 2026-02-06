"""
Pydantic Data Models for ThreatForest Tracing

This module defines the data models used for tracing ThreatForest workflows,
including input/output models for each capability, score models, and dataset
item schemas for Langfuse Datasets.

The models support:
- Threat Statement Generation tracing
- Attack Tree Generation tracing
- TTP (Tactics, Techniques, and Procedures) Matching tracing
- SME (Subject Matter Expert) scoring
- Langfuse Dataset items for evaluation
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# =============================================================================
# Enums
# =============================================================================


class TraceType(str, Enum):
    """
    Types of traces supported by the tracing system.
    
    Each trace type corresponds to a core ThreatForest capability:
    - THREAT_STATEMENT: Threat statement generation/validation
    - ATTACK_TREE: Attack tree generation from threat statements
    - TTP_MATCHING: MITRE ATT&CK technique matching
    """
    THREAT_STATEMENT = "threat_statement"
    ATTACK_TREE = "attack_tree"
    TTP_MATCHING = "ttp_matching"


class TraceStatus(str, Enum):
    """
    Review status of a trace.
    
    Traces progress through these statuses during the SME review workflow:
    - PENDING_REVIEW: Awaiting SME review
    - REVIEWED: SME has reviewed and scored the trace
    - GROUND_TRUTH: Approved as ground truth for evaluation datasets
    """
    PENDING_REVIEW = "pending_review"
    REVIEWED = "reviewed"
    GROUND_TRUTH = "ground_truth"


# =============================================================================
# Generation Metadata
# =============================================================================


class GenerationMetadata(BaseModel):
    """
    Metadata about LLM generation.
    
    Captures information about the LLM call that produced the output,
    including model identification, performance metrics, and configuration.
    
    Attributes:
        model_id: Identifier of the model used (e.g., "anthropic.claude-3-sonnet")
        prompt_version: Version identifier for the prompt template used
        latency_ms: Time taken for the generation in milliseconds
        input_tokens: Number of tokens in the input prompt
        output_tokens: Number of tokens in the generated output
        temperature: Temperature setting used for generation
    """
    model_id: str
    prompt_version: Optional[str] = None
    latency_ms: int
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    temperature: Optional[float] = None


# =============================================================================
# Threat Statement Models
# =============================================================================


class ThreatStatementInput(BaseModel):
    """
    Input for threat statement generation.
    
    Attributes:
        mode: The evaluation mode - one of:
            - "generate_new": Generate new threats from context
            - "validate_existing": Validate provided threats
            - "augment": Augment provided threats with additional ones
        context: Context information about the application being analyzed
        provided_threats: Optional list of user-provided threats (for validate/augment modes)
    """
    mode: str  # generate_new, validate_existing, augment
    context: Dict[str, Any]
    provided_threats: Optional[List[Dict[str, Any]]] = None


class ThreatStatementOutput(BaseModel):
    """
    Output from threat statement generation.
    
    Attributes:
        generated_threats: List of generated threat statements with their details
        threat_count: Total number of threats generated
    """
    generated_threats: List[Dict[str, Any]]
    threat_count: int


# =============================================================================
# Attack Tree Models
# =============================================================================


class AttackTreeInput(BaseModel):
    """
    Input for attack tree generation.
    
    Attributes:
        threat_statement: The threat statement to generate an attack tree for
        context: Additional context about the application
    """
    threat_statement: Dict[str, Any]
    context: Dict[str, Any]


class AttackTreeOutput(BaseModel):
    """
    Output from attack tree generation.
    
    Attributes:
        attack_tree_markdown: The generated attack tree in markdown format
        parsed_structure: Parsed tree structure with nodes and edges
    """
    attack_tree_markdown: str
    parsed_structure: Dict[str, Any]


class AutomatedMetrics(BaseModel):
    """
    Automated metrics for attack trees.
    
    Attributes:
        structural: Structural metrics including node_count, path_count,
                   max_depth, branching_factor, syntax_valid
        phase_coverage: Phase coverage metrics including phases_detected,
                       expected_phases, coverage_score
        technique_detection: Optional MITRE technique detection results
    """
    structural: Dict[str, Any]  # node_count, path_count, max_depth, etc.
    phase_coverage: Dict[str, Any]  # phases_detected, coverage_score
    technique_detection: Optional[Dict[str, Any]] = None


# =============================================================================
# TTP Matching Models
# =============================================================================


class TTPMatchingInput(BaseModel):
    """
    Input for TTP matching.
    
    Attributes:
        attack_step: The attack step to match, including node_id, label, node_type
        attack_matrix: The attack matrix to match against (default: MITRE ATT&CK Enterprise)
        context: Optional additional context for matching
    """
    attack_step: Dict[str, Any]  # node_id, label, node_type
    attack_matrix: str = "mitre_attack_enterprise"
    context: Optional[Dict[str, Any]] = None


class TTPMapping(BaseModel):
    """
    Single TTP mapping result.
    
    Attributes:
        rank: Ranking position of this mapping (1 = best match)
        technique_id: MITRE ATT&CK technique ID (e.g., "T1059.001")
        technique_name: Human-readable technique name
        tactic: The tactic this technique belongs to
        tactic_id: MITRE ATT&CK tactic ID (e.g., "TA0002")
        confidence: Overall confidence score (0.0 to 1.0)
        embedding_similarity: Similarity score from embedding comparison
        explanation: Optional explanation of why this technique was matched
    """
    rank: int
    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: str
    confidence: float
    embedding_similarity: float
    explanation: Optional[str] = None


class TTPMatchingOutput(BaseModel):
    """
    Output from TTP matching.
    
    Attributes:
        mappings: List of TTP mappings, ordered by rank
        top_k: Number of top mappings returned (default: 3)
    """
    mappings: List[TTPMapping]
    top_k: int = 3


# =============================================================================
# SME Score Model
# =============================================================================


class SMEScore(BaseModel):
    """
    SME-provided score.
    
    Represents a score assigned by a Subject Matter Expert during
    the review process.
    
    Attributes:
        name: Name of the score dimension (e.g., "overall_quality")
        value: Numeric score value (0.0 to 1.0)
        comment: Optional comment explaining the score
        reviewer_id: Optional identifier of the reviewer
        reviewed_at: Optional timestamp of when the review was done
    """
    name: str
    value: float
    comment: Optional[str] = None
    reviewer_id: Optional[str] = None
    reviewed_at: Optional[datetime] = None


# =============================================================================
# Evaluation Criteria Model
# =============================================================================


class EvaluationCriteria(BaseModel):
    """
    Criteria for evaluating outputs.
    
    Defines the evaluation criteria used by SMEs to assess the quality of
    ThreatForest outputs. These criteria are stored with dataset items
    to enable consistent evaluation.
    
    Attributes:
        structural: Structural requirements for attack trees (e.g., min_nodes,
                   min_paths, max_depth). Used to validate tree structure.
        required_phases: List of attack phases that must be present in the output
                        (e.g., ["initial_access", "execution", "persistence"])
        required_techniques: List of MITRE ATT&CK techniques that should be
                            identified, with optional metadata like tactic
        forbidden_patterns: List of patterns that should NOT appear in the output
                           (e.g., hallucinated techniques, invalid syntax)
        key_attack_paths: List of critical attack paths that must be represented
                         in the attack tree
        domain_requirements: Domain-specific requirements as key-value pairs
                            (e.g., {"industry": "healthcare", "compliance": "HIPAA"})
    """
    structural: Optional[Dict[str, Any]] = None  # min_nodes, min_paths, etc.
    required_phases: Optional[List[str]] = None
    required_techniques: Optional[List[Dict[str, Any]]] = None
    forbidden_patterns: Optional[List[str]] = None
    key_attack_paths: Optional[List[str]] = None
    domain_requirements: Optional[Dict[str, Any]] = None


# =============================================================================
# Dataset Item Models (for Langfuse Datasets)
# =============================================================================


class DatasetItemMetadata(BaseModel):
    """
    Metadata for a Langfuse Dataset item.
    
    This model captures the metadata stored with each dataset item,
    including trace provenance, scores, and evaluation criteria.
    
    Attributes:
        langfuse_trace_id: Original trace ID from Langfuse for cross-reference
        trace_type: Type of trace (threat_statement, attack_tree, ttp_matching)
        session_id: Session ID grouping related traces
        created_at: Timestamp when the trace was created
        review_status: Current review status
        generation_metadata: Optional LLM generation metadata
        scores: List of SME-provided scores
        is_ground_truth_candidate: Whether this trace is a ground truth candidate
        evaluation_criteria: Optional criteria for evaluating outputs
    """
    langfuse_trace_id: str
    trace_type: str
    session_id: Optional[str] = None
    created_at: Optional[str] = None
    review_status: str = "pending_review"
    generation_metadata: Optional[Dict[str, Any]] = None
    scores: List[Dict[str, Any]] = Field(default_factory=list)
    is_ground_truth_candidate: bool = False
    evaluation_criteria: Optional[Dict[str, Any]] = None


class DatasetItem(BaseModel):
    """
    A dataset item for Langfuse Datasets.
    
    Represents a single item in a Langfuse Dataset, containing the input,
    expected output, and metadata for evaluation.
    
    Attributes:
        input: The input data that was provided to the model
        expected_output: The reference/expected output for evaluation
        metadata: Additional metadata about the item
    
    Example:
        >>> item = DatasetItem(
        ...     input={"threat_statement": {"id": "T1", "description": "SQL Injection"}},
        ...     expected_output={"attack_tree_markdown": "# Attack Tree..."},
        ...     metadata=DatasetItemMetadata(
        ...         langfuse_trace_id="lf_123",
        ...         trace_type="attack_tree",
        ...         review_status="reviewed"
        ...     )
        ... )
    """
    input: Dict[str, Any]
    expected_output: Dict[str, Any]
    metadata: DatasetItemMetadata
