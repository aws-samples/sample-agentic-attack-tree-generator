"""
Core data models for ThreatForest application.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional


@dataclass
class ApplicationInfo:
    """Information extracted from application context files."""
    name: str
    description: str
    technologies: List[str] = field(default_factory=list)
    programming_languages: List[str] = field(default_factory=list)
    sector: str = ""
    security_objectives: List[str] = field(default_factory=list)  # CIA triad priorities
    additional_context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatStatement:
    """A parsed threat statement with metadata."""
    id: str
    title: str
    description: str
    severity: str  # low, medium, high
    category: str = ""
    impact: str = ""
    likelihood: str = ""
    source_file: str = ""
    line_number: int = 0


@dataclass
class AttackStep:
    """An individual step in an attack tree."""
    id: str
    description: str
    node_type: str  # attack, mitigation, goal, fact
    mitre_techniques: List[str] = field(default_factory=list)
    confidence_score: float = 0.0


@dataclass
class AttackTree:
    """A complete attack tree with metadata."""
    threat_id: str
    title: str
    mermaid_content: str
    attack_steps: List[AttackStep] = field(default_factory=list)
    file_path: str = ""
    generated_at: datetime = field(default_factory=datetime.now)


@dataclass
class STIXTechnique:
    """A MITRE ATT&CK technique from STIX data."""
    id: str
    name: str
    description: str
    tactic: str = ""
    technique_id: str = ""  # T1234
    sub_technique_id: Optional[str] = None  # T1234.001
    kill_chain_phases: List[str] = field(default_factory=list)