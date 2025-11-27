"""Pydantic models for attack tree structures"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum


class NodeType(str, Enum):
    """Attack tree node types with forest-themed semantics"""
    ATTACK = "attack"      # Attack step nodes (red branches)
    GOAL = "goal"          # End goal nodes (orange leaves)
    FACT = "fact"          # Starting condition nodes (blue roots)
    TECHNIQUE = "technique"  # MITRE ATT&CK technique nodes (brown branches)
    MITIGATION = "mitigation"  # Security control nodes (green protective leaves)


class AttackNode(BaseModel):
    """Individual node in an attack tree"""
    
    node_id: str = Field(
        description="Unique identifier for the node"
    )
    label: str = Field(
        description="Display label for the node"
    )
    node_type: NodeType = Field(
        description="Type of node (attack, goal, fact, technique, or mitigation)"
    )
    full_label: Optional[str] = Field(
        description="Full untruncated label text",
        default=None
    )
    color: Optional[str] = Field(
        description="Hex color code for visualization",
        default=None
    )


class AttackEdge(BaseModel):
    """Edge connecting nodes in attack tree"""
    
    from_node: str = Field(
        description="Source node ID",
        alias="from"
    )
    to_node: str = Field(
        description="Target node ID",
        alias="to"
    )


class TTPMapping(BaseModel):
    """MITRE ATT&CK TTP mapping for an attack step"""
    
    attack_step: str = Field(
        description="The attack step being mapped"
    )
    technique_id: str = Field(
        description="MITRE ATT&CK technique ID (e.g., T1190)"
    )
    technique_name: str = Field(
        description="Human-readable technique name"
    )
    confidence: float = Field(
        description="Similarity/confidence score (0.0 to 1.0)",
        ge=0.0,
        le=1.5  # Allow AWS boost up to 1.5
    )
    tactics: List[str] = Field(
        description="MITRE ATT&CK tactics",
        default_factory=list
    )
    technique_url: Optional[str] = Field(
        description="Link to MITRE ATT&CK page",
        default=None
    )
    mitigations: Optional[List[Dict[str, Any]]] = Field(
        description="Security mitigations for this technique",
        default=None
    )


class AttackTreeMetadata(BaseModel):
    """Metadata for an attack tree"""
    
    threat_id: str = Field(
        description="Unique threat identifier"
    )
    threat_statement: str = Field(
        description="Full threat statement"
    )
    threat_category: str = Field(
        description="Threat category (e.g., Authentication, Data Breach)"
    )
    threat_severity: Optional[str] = Field(
        description="Threat severity: High, Medium, or Low",
        default=None
    )


class AttackTree(BaseModel):
    """Complete attack tree structure"""
    
    threat_id: str = Field(
        description="Unique threat identifier"
    )
    threat_statement: str = Field(
        description="Full threat statement"
    )
    threat_category: str = Field(
        description="Threat category"
    )
    mermaid_code: str = Field(
        description="Mermaid diagram code"
    )
    nodes: Optional[List[AttackNode]] = Field(
        description="List of nodes in the tree",
        default=None
    )
    edges: Optional[List[AttackEdge]] = Field(
        description="List of edges connecting nodes",
        default=None
    )
    ttc_mappings: List[TTPMapping] = Field(
        description="MITRE ATT&CK technique mappings",
        default_factory=list
    )
    mapping_count: Optional[int] = Field(
        description="Total number of technique mappings",
        default=None
    )


class AttackTreeGenerationResult(BaseModel):
    """Result from attack tree generation"""
    
    attack_trees: List[AttackTree] = Field(
        description="Generated attack trees"
    )
    threat_status: Dict[str, str] = Field(
        description="Status of each threat (success/failed)",
        default_factory=dict
    )
    generation_summary: Dict[str, int] = Field(
        description="Summary statistics",
        default_factory=dict
    )
