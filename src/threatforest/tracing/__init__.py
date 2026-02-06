"""
ThreatForest Tracing Module

This module provides Langfuse-based tracing infrastructure for ThreatForest workflows.
It supports OpenTelemetry-based tracing, SME review workflows, and Langfuse Dataset export.

The module implements a no-op fallback when tracing is disabled, ensuring backward
compatibility with existing workflows.
"""

from threatforest.tracing.config import LangfuseConfig
from threatforest.tracing.context import TracingContext
from threatforest.tracing.export import ExportFilter, LangfuseDatasetExporter, LangfuseExporter
from threatforest.tracing.interfaces import (
    IGeneration,
    ISpan,
    ITrace,
    ITracingManager,
)
from threatforest.tracing.manager import (
    LangfuseSpan,
    LangfuseTrace,
    TracingManager,
    get_tracing_manager,
)
from threatforest.tracing.metrics import (
    ATTACK_PHASES,
    PHASE_KEYWORDS,
    PhaseCoverage,
    StructuralMetrics,
    TechniqueDetection,
    add_mermaid_visualization_to_output,
    calculate_automated_metrics,
    calculate_phase_coverage,
    calculate_structural_metrics,
    detect_mitre_techniques,
    generate_mermaid_live_link,
)
from threatforest.tracing.models import (
    AttackTreeInput,
    AttackTreeOutput,
    AutomatedMetrics,
    DatasetItem,
    DatasetItemMetadata,
    EvaluationCriteria,
    GenerationMetadata,
    SMEScore,
    ThreatStatementInput,
    ThreatStatementOutput,
    TraceStatus,
    TraceType,
    TTPMapping,
    TTPMatchingInput,
    TTPMatchingOutput,
)
from threatforest.tracing.noop import (
    NoOpGeneration,
    NoOpSpan,
    NoOpTrace,
    NoOpTracingManager,
)
from threatforest.tracing.resilient import (
    BufferedSpan,
    BufferedSpanWrapper,
    BufferedTrace,
    BufferedTraceWrapper,
    ResilientTracingManager,
    get_resilient_tracing_manager,
)
from threatforest.tracing.scores import (
    ATTACK_TREE_SCORES,
    THREAT_STATEMENT_SCORES,
    TTP_MAPPING_SCORES,
    TTP_SCORE_VALUES,
    ScoreDefinition,
    ScoreType,
    get_all_score_definitions,
    get_score_definition,
    get_ttp_numeric_value,
)
from threatforest.tracing.score_configs import (
    RegisteredScoreConfig,
    ScoreConfigRegistry,
    get_score_config_registry,
    reset_score_config_registry,
)

__all__ = [
    # Configuration
    "LangfuseConfig",
    # Context managers
    "TracingContext",
    # Export
    "ExportFilter",
    "LangfuseDatasetExporter",
    "LangfuseExporter",  # Backwards compatibility alias
    # Interfaces
    "IGeneration",
    "ISpan",
    "ITrace",
    "ITracingManager",
    # Langfuse implementations
    "LangfuseSpan",
    "LangfuseTrace",
    "TracingManager",
    "get_tracing_manager",
    # Metrics
    "ATTACK_PHASES",
    "PHASE_KEYWORDS",
    "StructuralMetrics",
    "PhaseCoverage",
    "TechniqueDetection",
    "calculate_structural_metrics",
    "calculate_phase_coverage",
    "detect_mitre_techniques",
    "calculate_automated_metrics",
    "generate_mermaid_live_link",
    "add_mermaid_visualization_to_output",
    # Data Models
    "TraceType",
    "TraceStatus",
    "GenerationMetadata",
    "ThreatStatementInput",
    "ThreatStatementOutput",
    "AttackTreeInput",
    "AttackTreeOutput",
    "AutomatedMetrics",
    "TTPMatchingInput",
    "TTPMapping",
    "TTPMatchingOutput",
    "SMEScore",
    "EvaluationCriteria",
    "DatasetItem",
    "DatasetItemMetadata",
    # No-op implementations
    "NoOpGeneration",
    "NoOpSpan",
    "NoOpTrace",
    "NoOpTracingManager",
    # Resilient implementations
    "BufferedTrace",
    "BufferedTraceWrapper",
    "BufferedSpan",
    "BufferedSpanWrapper",
    "ResilientTracingManager",
    "get_resilient_tracing_manager",
    # Score definitions
    "ScoreType",
    "ScoreDefinition",
    "THREAT_STATEMENT_SCORES",
    "ATTACK_TREE_SCORES",
    "TTP_MAPPING_SCORES",
    "TTP_SCORE_VALUES",
    "get_score_definition",
    "get_ttp_numeric_value",
    "get_all_score_definitions",
    # Score config registration
    "RegisteredScoreConfig",
    "ScoreConfigRegistry",
    "get_score_config_registry",
    "reset_score_config_registry",
]
