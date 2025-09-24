"""
Data models for ThreatForest application.

This module defines Pydantic models for all data structures used throughout
the ThreatForest system, including context information, threat statements,
attack trees, and TTC mappings.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum

from pydantic import BaseModel, Field, field_validator


class SeverityLevel(str, Enum):
    """Enumeration for threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ValidationStatus(str, Enum):
    """Enumeration for validation status."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    MODIFIED = "modified"


class AttackStepType(str, Enum):
    """Enumeration for attack step types in Mermaid diagrams."""
    ATTACK = "attack"
    MITIGATION = "mitigation"
    GOAL = "goal"
    FACT = "fact"


class ContextInformation(BaseModel):
    """
    Model for extracted context information from application files.
    
    This model stores all security-relevant information extracted from
    README files, architecture diagrams, and other context documents.
    """
    
    technologies: List[str] = Field(
        default_factory=list,
        description="List of technologies and frameworks used"
    )
    programming_languages: List[str] = Field(
        default_factory=list,
        description="Programming languages identified in the project"
    )
    sector: Optional[str] = Field(
        None,
        description="Business sector or industry domain"
    )
    security_objectives: List[str] = Field(
        default_factory=list,
        description="Security objectives (Confidentiality, Integrity, Availability)"
    )
    architecture_type: Optional[str] = Field(
        None,
        description="Type of architecture (e.g., microservices, monolithic)"
    )
    compliance_frameworks: List[str] = Field(
        default_factory=list,
        description="Compliance frameworks mentioned (SOC2, PCI-DSS, etc.)"
    )
    extracted_from: List[str] = Field(
        default_factory=list,
        description="Source files from which information was extracted"
    )
    validation_status: ValidationStatus = Field(
        ValidationStatus.PENDING,
        description="Current validation status of the extracted information"
    )
    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="Timestamp when information was extracted"
    )
    confidence_score: float = Field(
        0.0,
        ge=0.0,
        le=1.0,
        description="Confidence score for the extracted information"
    )
    
    @field_validator('security_objectives')
    @classmethod
    def validate_security_objectives(cls, v):
        """Validate that security objectives are from the CIA triad."""
        valid_objectives = {'confidentiality', 'integrity', 'availability'}
        for objective in v:
            if objective.lower() not in valid_objectives:
                raise ValueError(f"Invalid security objective: {objective}")
        return v
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary for serialization."""
        return self.model_dump()
    
    def to_yaml_dict(self) -> Dict[str, Any]:
        """Convert model to YAML-friendly dictionary."""
        data = self.model_dump()
        data['timestamp'] = self.timestamp.isoformat()
        return data


class ThreatStatement(BaseModel):
    """
    Model for parsed threat statements.
    
    Represents a structured threat statement with all components
    needed for attack tree generation.
    """
    
    id: str = Field(
        ...,
        description="Unique identifier for the threat statement"
    )
    severity: SeverityLevel = Field(
        ...,
        description="Severity level of the threat"
    )
    threat_source: str = Field(
        ...,
        description="Source or actor of the threat"
    )
    prerequisites: str = Field(
        ...,
        description="Prerequisites or conditions for the threat"
    )
    threat_action: str = Field(
        ...,
        description="Action performed by the threat actor"
    )
    threat_impact: str = Field(
        ...,
        description="Impact or consequence of the threat"
    )
    impacted_assets: List[str] = Field(
        default_factory=list,
        description="Assets affected by the threat"
    )
    impacted_goals: List[str] = Field(
        default_factory=list,
        description="Security goals impacted (CIA triad)"
    )
    raw_statement: str = Field(
        ...,
        description="Original raw threat statement text"
    )
    
    @field_validator('impacted_goals')
    @classmethod
    def validate_impacted_goals(cls, v):
        """Validate that impacted goals are from the CIA triad."""
        valid_goals = {'confidentiality', 'integrity', 'availability'}
        for goal in v:
            if goal.lower() not in valid_goals:
                raise ValueError(f"Invalid impacted goal: {goal}")
        return v
    
    def is_high_severity(self) -> bool:
        """Check if threat is high severity."""
        return self.severity == SeverityLevel.HIGH
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary for serialization."""
        return self.dict()


class AttackStep(BaseModel):
    """
    Model for individual attack steps in an attack tree.
    """
    
    id: str = Field(
        ...,
        description="Unique identifier for the attack step"
    )
    description: str = Field(
        ...,
        description="Description of the attack step"
    )
    step_type: AttackStepType = Field(
        ...,
        description="Type of step (attack, mitigation, goal, fact)"
    )
    dependencies: List[str] = Field(
        default_factory=list,
        description="List of prerequisite step IDs"
    )
    ttc_reference: Optional[str] = Field(
        None,
        description="TTC technique reference if mapped"
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary for serialization."""
        return self.dict()


class TTCMapping(BaseModel):
    """
    Model for TTC (Threat Technique Catalog) mappings.
    
    Represents the mapping between attack steps and STIX techniques
    from the AAF bundle.
    """
    
    attack_step_id: str = Field(
        ...,
        description="ID of the attack step being mapped"
    )
    ttc_technique_id: str = Field(
        ...,
        description="TTC technique identifier from STIX data"
    )
    ttc_technique_name: str = Field(
        ...,
        description="Human-readable name of the TTC technique"
    )
    alignment_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Semantic alignment score (0.0 to 1.0)"
    )
    stix_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Raw STIX data for the technique"
    )
    applied: bool = Field(
        False,
        description="Whether this mapping has been applied to the attack tree"
    )
    
    @field_validator('alignment_score')
    @classmethod
    def validate_alignment_score(cls, v):
        """Validate alignment score is above threshold for application."""
        if v < 0.0 or v > 1.0:
            raise ValueError("Alignment score must be between 0.0 and 1.0")
        return v
    
    def is_strong_alignment(self, threshold: float = 0.8) -> bool:
        """Check if alignment score meets the threshold for application."""
        return self.alignment_score >= threshold
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary for serialization."""
        return self.dict()


class AttackTree(BaseModel):
    """
    Model for generated attack trees.
    
    Represents a complete attack tree with Mermaid content and metadata.
    """
    
    threat_id: str = Field(
        ...,
        description="ID of the threat statement this tree represents"
    )
    title: str = Field(
        ...,
        description="Title of the attack tree"
    )
    mermaid_content: str = Field(
        ...,
        description="Generated Mermaid diagram content"
    )
    attack_steps: List[AttackStep] = Field(
        default_factory=list,
        description="List of attack steps in the tree"
    )
    ttc_mappings: Dict[str, TTCMapping] = Field(
        default_factory=dict,
        description="TTC mappings applied to attack steps"
    )
    generated_timestamp: datetime = Field(
        default_factory=datetime.now,
        description="Timestamp when the attack tree was generated"
    )
    context_info: Optional[ContextInformation] = Field(
        None,
        description="Context information used for generation"
    )
    
    def get_step_by_id(self, step_id: str) -> Optional[AttackStep]:
        """Get an attack step by its ID."""
        for step in self.attack_steps:
            if step.id == step_id:
                return step
        return None
    
    def add_ttc_mapping(self, mapping: TTCMapping) -> None:
        """Add a TTC mapping to the attack tree."""
        self.ttc_mappings[mapping.attack_step_id] = mapping
    
    def get_high_confidence_mappings(self, threshold: float = 0.8) -> List[TTCMapping]:
        """Get TTC mappings above the confidence threshold."""
        return [
            mapping for mapping in self.ttc_mappings.values()
            if mapping.is_strong_alignment(threshold)
        ]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary for serialization."""
        data = self.dict()
        data['generated_timestamp'] = self.generated_timestamp.isoformat()
        return data
    
    def to_yaml_dict(self) -> Dict[str, Any]:
        """Convert model to YAML-friendly dictionary."""
        return self.to_dict()


class AnalysisResult(BaseModel):
    """
    Model for complete analysis results.
    
    Represents the output of a complete ThreatForest analysis run.
    """
    
    context_info: ContextInformation = Field(
        ...,
        description="Extracted context information"
    )
    threat_statements: List[ThreatStatement] = Field(
        default_factory=list,
        description="Parsed threat statements"
    )
    attack_trees: List[AttackTree] = Field(
        default_factory=list,
        description="Generated attack trees"
    )
    analysis_timestamp: datetime = Field(
        default_factory=datetime.now,
        description="Timestamp of the analysis"
    )
    source_directory: str = Field(
        ...,
        description="Directory that was analyzed"
    )
    output_directory: str = Field(
        ...,
        description="Directory where outputs were saved"
    )
    
    def get_high_severity_threats(self) -> List[ThreatStatement]:
        """Get only high-severity threat statements."""
        return [
            threat for threat in self.threat_statements
            if threat.is_high_severity()
        ]
    
    def get_attack_tree_count(self) -> int:
        """Get the number of generated attack trees."""
        return len(self.attack_trees)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary for serialization."""
        data = self.dict()
        data['analysis_timestamp'] = self.analysis_timestamp.isoformat()
        return data