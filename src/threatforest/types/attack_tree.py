"""Attack tree models produced by the Tree Generator."""

from dataclasses import dataclass, field


@dataclass
class AttackStep:
    id: str = ""
    description: str = ""
    parent_id: str = ""
    is_leaf: bool = False
    feasibility_note: str = ""  # set by Tree Verifier if low-confidence
    # Attacker factors emitted by the Tree Generator (empty on fact node).
    skill_required: str = ""      # low|med|high
    access_required: str = ""     # none|authenticated|privileged
    detectability: str = ""       # low|med|high
    exploit_maturity: str = ""    # theoretical|poc|weaponised
    # Computed by the probability stage.
    probability: float = 0.0
    probability_rationale: str = ""
    reach_probability: float = 0.0


@dataclass
class AttackTree:
    id: str = ""
    threat_id: str = ""
    root_goal: str = ""
    steps: list[AttackStep] = field(default_factory=list)
