"""Mitigation models for the Mitigation pipeline."""

from dataclasses import dataclass, field


@dataclass
class Evidence:
    source_type: str = ""  # "control_catalog" | "attack_technique" | "project_file"
    source_ref: str = ""
    excerpt: str = ""
    relevance: str = ""


@dataclass
class ControlCandidate:
    control_id: str = ""
    control_name: str = ""
    control_description: str = ""
    similarity_score: float = 0.0
    rank: int = 0


@dataclass
class Mitigation:
    attack_step_id: str = ""
    technique_id: str = ""
    mitigation_text: str = ""
    implementation_guidance: str = ""
    control_candidates: list[ControlCandidate] = field(default_factory=list)
    selected_control_id: str = ""
    priority: int = 0
    evidence: list[Evidence] = field(default_factory=list)
