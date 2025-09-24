"""
Agent modules for ThreatForest multi-agent system.
"""

from .context_detection import (
    ContextDetectionAgent,
    DetectedFile,
    ContextScanResult,
    FileType,
    FileFormat
)

from .information_extraction import (
    InformationExtractionAgent,
    ExtractionResult
)

from .attack_tree_generator import (
    AttackTreeGeneratorAgent,
    AttackPath,
    GenerationResult
)

from .ttc_mapping import (
    TTCMappingAgent,
    MappingResult
)

from .orchestrator import (
    OrchestratorAgent
)

__all__ = [
    "ContextDetectionAgent",
    "DetectedFile",
    "ContextScanResult", 
    "FileType",
    "FileFormat",
    "InformationExtractionAgent",
    "ExtractionResult",
    "AttackTreeGeneratorAgent",
    "AttackPath",
    "GenerationResult",
    "TTCMappingAgent",
    "MappingResult",
    "OrchestratorAgent",
]