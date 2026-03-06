"""TTP mapping models for the TTP pipeline."""

from dataclasses import dataclass, field


@dataclass
class TTPCandidate:
    technique_id: str = ""
    technique_name: str = ""
    similarity_score: float = 0.0
    rank: int = 0


@dataclass
class TTPMapping:
    attack_step_id: str = ""
    technique_id: str = ""
    technique_name: str = ""
    similarity_score: float = 0.0
    top_k_candidates: list[TTPCandidate] = field(default_factory=list)
    reviewer_overrode_top1: bool = False
    reviewer_reasoning: str = ""
