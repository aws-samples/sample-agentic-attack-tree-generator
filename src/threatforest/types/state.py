"""File-based state passing models for graph nodes."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NodeResult:
    """Result from a graph node — lightweight pointer to state file."""

    state_file: str
    summary: str
    route: str  # "pass" | "reject" | "feedback"
    feedback: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 2

    @property
    def should_retry(self) -> bool:
        return self.route == "reject" and self.retry_count < self.max_retries

    @property
    def over_budget(self) -> bool:
        return self.route == "reject" and self.retry_count >= self.max_retries
