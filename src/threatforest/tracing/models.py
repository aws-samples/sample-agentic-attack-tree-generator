"""
Pydantic Data Models for ThreatForest Tracing

This module defines the data models used for tracing ThreatForest workflows,
including input/output models for each capability, score models, and the
DynamoDB record schema for export.

The models support:
- Threat Statement Generation tracing
- Attack Tree Generation tracing
- TTP (Tactics, Techniques, and Procedures) Matching tracing
- SME (Subject Matter Expert) scoring
- DynamoDB export with proper key structure

Requirements:
- 7.2: THE Export_Pipeline SHALL transform Langfuse trace data to the DynamoDB
       schema with PK format TRACE#{trace_type}#{trace_id}
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
    
    Example:
        >>> metadata = GenerationMetadata(
        ...     model_id="anthropic.claude-3-sonnet",
        ...     latency_ms=1500,
        ...     input_tokens=500,
        ...     output_tokens=200
        ... )
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
    
    Captures the input parameters for the threat statement generation stage,
    including the evaluation mode and context information.
    
    Attributes:
        mode: The evaluation mode - one of:
            - "generate_new": Generate new threats from context
            - "validate_existing": Validate provided threats
            - "augment": Augment provided threats with additional ones
        context: Context information about the application being analyzed
        provided_threats: Optional list of user-provided threats (for validate/augment modes)
    
    Example:
        >>> input_data = ThreatStatementInput(
        ...     mode="generate_new",
        ...     context={"application_type": "web_api", "tech_stack": ["python", "aws"]}
        ... )
    """
    mode: str  # generate_new, validate_existing, augment
    context: Dict[str, Any]
    provided_threats: Optional[List[Dict[str, Any]]] = None


class ThreatStatementOutput(BaseModel):
    """
    Output from threat statement generation.
    
    Captures the results of the threat statement generation stage.
    
    Attributes:
        generated_threats: List of generated threat statements with their details
        threat_count: Total number of threats generated
    
    Example:
        >>> output = ThreatStatementOutput(
        ...     generated_threats=[{"id": "T1", "description": "SQL Injection"}],
        ...     threat_count=1
        ... )
    """
    generated_threats: List[Dict[str, Any]]
    threat_count: int


# =============================================================================
# Attack Tree Models
# =============================================================================


class AttackTreeInput(BaseModel):
    """
    Input for attack tree generation.
    
    Captures the input parameters for generating an attack tree from
    a threat statement.
    
    Attributes:
        threat_statement: The threat statement to generate an attack tree for
        context: Additional context about the application
    
    Example:
        >>> input_data = AttackTreeInput(
        ...     threat_statement={"id": "T1", "description": "SQL Injection"},
        ...     context={"database": "postgresql"}
        ... )
    """
    threat_statement: Dict[str, Any]
    context: Dict[str, Any]


class AttackTreeOutput(BaseModel):
    """
    Output from attack tree generation.
    
    Captures the results of the attack tree generation stage.
    
    Attributes:
        attack_tree_markdown: The generated attack tree in markdown format
        parsed_structure: Parsed tree structure with nodes and edges
    
    Example:
        >>> output = AttackTreeOutput(
        ...     attack_tree_markdown="# Root\\n## Step 1",
        ...     parsed_structure={"nodes": ["Root", "Step 1"], "edges": [(0, 1)]}
        ... )
    """
    attack_tree_markdown: str
    parsed_structure: Dict[str, Any]


class AutomatedMetrics(BaseModel):
    """
    Automated metrics for attack trees.
    
    Captures automatically calculated metrics about attack tree quality,
    including structural analysis and phase coverage.
    
    Attributes:
        structural: Structural metrics including node_count, path_count,
                   max_depth, branching_factor, syntax_valid
        phase_coverage: Phase coverage metrics including phases_detected,
                       expected_phases, coverage_score
        technique_detection: Optional MITRE technique detection results
    
    Example:
        >>> metrics = AutomatedMetrics(
        ...     structural={"node_count": 10, "max_depth": 3},
        ...     phase_coverage={"coverage_score": 0.75}
        ... )
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
    
    Captures the input parameters for matching attack steps to
    MITRE ATT&CK techniques.
    
    Attributes:
        attack_step: The attack step to match, including node_id, label, node_type
        attack_matrix: The attack matrix to match against (default: MITRE ATT&CK Enterprise)
        context: Optional additional context for matching
    
    Example:
        >>> input_data = TTPMatchingInput(
        ...     attack_step={"node_id": "1", "label": "Execute PowerShell", "node_type": "action"},
        ...     attack_matrix="mitre_attack_enterprise"
        ... )
    """
    attack_step: Dict[str, Any]  # node_id, label, node_type
    attack_matrix: str = "mitre_attack_enterprise"
    context: Optional[Dict[str, Any]] = None


class TTPMapping(BaseModel):
    """
    Single TTP mapping result.
    
    Represents a single technique mapping from the TTP matching process,
    including confidence scores and explanations.
    
    Attributes:
        rank: Ranking position of this mapping (1 = best match)
        technique_id: MITRE ATT&CK technique ID (e.g., "T1059.001")
        technique_name: Human-readable technique name
        tactic: The tactic this technique belongs to
        tactic_id: MITRE ATT&CK tactic ID (e.g., "TA0002")
        confidence: Overall confidence score (0.0 to 1.0)
        embedding_similarity: Similarity score from embedding comparison
        explanation: Optional explanation of why this technique was matched
    
    Example:
        >>> mapping = TTPMapping(
        ...     rank=1,
        ...     technique_id="T1059.001",
        ...     technique_name="PowerShell",
        ...     tactic="Execution",
        ...     tactic_id="TA0002",
        ...     confidence=0.95,
        ...     embedding_similarity=0.92
        ... )
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
    
    Captures the results of the TTP matching process, including
    all candidate mappings.
    
    Attributes:
        mappings: List of TTP mappings, ordered by rank
        top_k: Number of top mappings returned (default: 3)
    
    Example:
        >>> output = TTPMatchingOutput(
        ...     mappings=[TTPMapping(rank=1, technique_id="T1059", ...)],
        ...     top_k=3
        ... )
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
    
    Example:
        >>> score = SMEScore(
        ...     name="overall_quality",
        ...     value=0.85,
        ...     comment="Good coverage but missing some edge cases",
        ...     reviewer_id="sme_user_123"
        ... )
    """
    name: str
    value: float
    comment: Optional[str] = None
    reviewer_id: Optional[str] = None
    reviewed_at: Optional[datetime] = None


# =============================================================================
# DynamoDB Record Model
# =============================================================================


class TraceRecord(BaseModel):
    """
    Complete trace record for DynamoDB.
    
    This model represents the full trace record as stored in DynamoDB,
    including the key structure, metadata, and all associated data.
    
    The DynamoDB key structure follows the pattern:
    - PK: TRACE#{trace_type}#{trace_id}
    - SK: META (for the main record)
    
    Attributes:
        PK: Primary key in format TRACE#{trace_type}#{trace_id}
        SK: Sort key, defaults to "META"
        trace_id: Unique identifier for this trace
        trace_type: Type of trace (threat_statement, attack_tree, ttp_matching)
        langfuse_trace_id: Cross-reference ID to Langfuse
        created_at: Timestamp when the trace was created
        session_id: Session ID grouping related traces
        input: Input data for the traced operation
        output: Output data from the traced operation
        generation_metadata: Optional LLM generation metadata
        automated_metrics: Optional automated metrics (for attack trees)
        scores: List of SME-provided scores
        review_status: Current review status
        is_ground_truth_candidate: Whether this trace is a ground truth candidate
        ttl: Optional TTL timestamp for automatic deletion (Unix timestamp)
    
    Example:
        >>> record = TraceRecord(
        ...     PK="TRACE#attack_tree#abc123",
        ...     trace_id="abc123",
        ...     trace_type=TraceType.ATTACK_TREE,
        ...     langfuse_trace_id="lf_xyz789",
        ...     created_at=datetime.now(),
        ...     session_id="session_456",
        ...     input={"threat_statement": {...}},
        ...     output={"attack_tree_markdown": "..."}
        ... )
    """
    PK: str  # TRACE#{trace_type}#{trace_id}
    SK: str = "META"
    trace_id: str
    trace_type: TraceType
    langfuse_trace_id: str
    created_at: datetime
    session_id: str
    input: Dict[str, Any]
    output: Dict[str, Any]
    generation_metadata: Optional[GenerationMetadata] = None
    automated_metrics: Optional[AutomatedMetrics] = None
    scores: List[SMEScore] = Field(default_factory=list)
    review_status: TraceStatus = TraceStatus.PENDING_REVIEW
    is_ground_truth_candidate: bool = False
    ttl: Optional[int] = None  # Unix timestamp for TTL


# =============================================================================
# Ground Truth Models
# =============================================================================


class EvaluationCriteria(BaseModel):
    """
    Criteria for evaluating outputs.
    
    Defines the evaluation criteria used by SMEs to assess the quality of
    ThreatForest outputs. These criteria are stored with ground truth records
    to enable consistent evaluation across datasets.
    
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
    
    Requirements:
        - 10.4: THE Export_Pipeline SHALL preserve SME-defined evaluation_criteria
                including required_phases, required_techniques, and forbidden_patterns
    
    Example:
        >>> criteria = EvaluationCriteria(
        ...     structural={"min_nodes": 5, "min_paths": 2, "max_depth": 4},
        ...     required_phases=["initial_access", "execution"],
        ...     required_techniques=[
        ...         {"technique_id": "T1059", "tactic": "execution"},
        ...         {"technique_id": "T1003", "tactic": "credential_access"}
        ...     ],
        ...     forbidden_patterns=["UNKNOWN_TECHNIQUE", "TODO"],
        ...     key_attack_paths=["phishing -> execution -> persistence"],
        ...     domain_requirements={"industry": "finance", "data_sensitivity": "high"}
        ... )
    """
    structural: Optional[Dict[str, Any]] = None  # min_nodes, min_paths, etc.
    required_phases: Optional[List[str]] = None
    required_techniques: Optional[List[Dict[str, Any]]] = None
    forbidden_patterns: Optional[List[str]] = None
    key_attack_paths: Optional[List[str]] = None
    domain_requirements: Optional[Dict[str, Any]] = None


class GroundTruthRecord(BaseModel):
    """
    Ground truth record for evaluation datasets.
    
    Represents an SME-approved example used for model evaluation and training.
    Ground truth records are stored in a separate DynamoDB table without TTL
    to preserve them indefinitely.
    
    The DynamoDB key structure follows the pattern:
    - PK: GT#{type}#{id}
    - SK: META (for the main record)
    
    Attributes:
        PK: Primary key in format GT#{type}#{id}
        SK: Sort key, defaults to "META"
        ground_truth_id: Unique identifier for this ground truth record
        type: Type of ground truth (threat_statement, attack_tree, ttp_matching)
        source_trace_id: ID of the original trace this ground truth was derived from
        created_at: Timestamp when the ground truth was created
        created_by: Identifier of the SME who approved this as ground truth
        dataset_id: Identifier of the dataset this record belongs to
        split: Dataset split assignment (train, eval, or test)
        input: The input data that produced the reference output
        reference_output: The SME-approved reference output
        evaluation_criteria: Criteria for evaluating outputs against this ground truth
        metadata: Additional metadata as key-value pairs
    
    Requirements:
        - 10.2: THE Export_Pipeline SHALL export approved ground truth to
                threatforest-ground-truth table with evaluation_criteria
        - 10.3: THE Export_Pipeline SHALL support dataset versioning with
                dataset_id and split (train/eval/test) attributes
        - 10.4: THE Export_Pipeline SHALL preserve SME-defined evaluation_criteria
    
    Example:
        >>> ground_truth = GroundTruthRecord(
        ...     PK="GT#attack_tree#gt_abc123",
        ...     ground_truth_id="gt_abc123",
        ...     type=TraceType.ATTACK_TREE,
        ...     source_trace_id="trace_xyz789",
        ...     created_at=datetime.now(),
        ...     created_by="sme_user_456",
        ...     dataset_id="dataset_v1.0",
        ...     split="train",
        ...     input={"threat_statement": {"id": "T1", "description": "SQL Injection"}},
        ...     reference_output={"attack_tree_markdown": "# SQL Injection Attack Tree..."},
        ...     evaluation_criteria=EvaluationCriteria(
        ...         required_phases=["initial_access", "execution"],
        ...         structural={"min_nodes": 5}
        ...     ),
        ...     metadata={"review_notes": "Excellent example of SQL injection attack tree"}
        ... )
    """
    PK: str  # GT#{type}#{id}
    SK: str = "META"
    ground_truth_id: str
    type: TraceType
    source_trace_id: str
    created_at: datetime
    created_by: str
    dataset_id: str
    split: str  # train, eval, test
    input: Dict[str, Any]
    reference_output: Dict[str, Any]
    evaluation_criteria: EvaluationCriteria
    metadata: Dict[str, Any] = Field(default_factory=dict)
