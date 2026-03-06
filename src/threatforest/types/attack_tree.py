"""Attack tree models produced by the Tree Generator."""

from dataclasses import dataclass, field


@dataclass
class AttackStep:
    id: str = ""
    description: str = ""
    parent_id: str = ""
    is_leaf: bool = False
    feasibility_note: str = ""  # set by Tree Verifier if low-confidence


@dataclass
class AttackTree:
    id: str = ""
    threat_id: str = ""
    root_goal: str = ""
    steps: list[AttackStep] = field(default_factory=list)
