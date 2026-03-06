"""Project context produced by the Scanner Agent."""

from dataclasses import dataclass, field


@dataclass
class ProjectContext:
    tech_stack: str = ""
    cloud_provider: str = ""  # "aws", "gcp", "azure", "hybrid", "none"
    services: list[str] = field(default_factory=list)
    auth_mechanisms: list[str] = field(default_factory=list)
    security_controls: dict[str, str] = field(default_factory=dict)
    data_flows: list[str] = field(default_factory=list)
    files_analyzed: list[str] = field(default_factory=list)
    files_skipped_reason: list[str] = field(default_factory=list)
    repo_size_category: str = ""  # "small" (<50 files) | "large"
