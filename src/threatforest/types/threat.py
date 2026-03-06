"""Threat models produced by the Threat Agent."""

from dataclasses import dataclass, field


@dataclass
class Threat:
    id: str = ""
    title: str = ""
    description: str = ""
    threat_source: str = ""  # "generated" | "user_provided"
    affected_components: list[str] = field(default_factory=list)
