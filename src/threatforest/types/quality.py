"""Quality warnings emitted when nodes exceed retry budget."""

from dataclasses import dataclass


@dataclass
class QualityWarning:
    node_id: str = ""
    message: str = ""
    severity: str = ""  # "low" | "medium" | "high"
