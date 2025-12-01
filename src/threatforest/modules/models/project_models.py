"""Pydantic models for project information and analysis results"""
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class ContextFiles(BaseModel):
    """Categorized file paths discovered during context analysis"""
    
    threat_models: List[str] = Field(
        description="Paths to threat model files",
        default_factory=list
    )
    readmes: List[str] = Field(
        description="Paths to README files",
        default_factory=list
    )
    architecture_diagrams: List[str] = Field(
        description="Paths to architecture diagram files",
        default_factory=list
    )
    data_flow_diagrams: List[str] = Field(
        description="Paths to data flow diagram files",
        default_factory=list
    )
    other_docs: List[str] = Field(
        description="Paths to other documentation files",
        default_factory=list
    )
    project_path: Optional[str] = Field(
        description="Path to the project root directory",
        default=None
    )
    enhanced_context: Optional[Dict[str, Any]] = Field(
        description="Enhanced context extracted from project files",
        default=None
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for backward compatibility"""
        return self.model_dump(exclude_none=False)


class ProjectInfo(BaseModel):
    """Project metadata and analysis results"""
    
    application_name: str = Field(
        description="Name of the application being analyzed",
        default="Unknown Application"
    )
    technologies: List[str] = Field(
        description="List of technologies used in the project",
        default_factory=list
    )
    architecture_type: str = Field(
        description="Type of architecture (e.g., microservices, monolith)",
        default="Unknown"
    )
    deployment_environment: str = Field(
        description="Where the application is deployed (e.g., AWS, on-premise)",
        default="Unknown"
    )
    sector: str = Field(
        description="Industry sector (e.g., healthcare, finance)",
        default="Unknown"
    )
    security_objectives: List[str] = Field(
        description="List of security objectives",
        default_factory=list
    )
    data_assets: List[str] = Field(
        description="Sensitive data identified",
        default_factory=list
    )
    entry_points: List[str] = Field(
        description="External interfaces and APIs",
        default_factory=list
    )
    trust_boundaries: List[str] = Field(
        description="Security boundaries in the system",
        default_factory=list
    )
    summary: Optional[str] = Field(
        description="Brief summary of findings",
        default=None
    )


class ExtractionSummary(BaseModel):
    """Summary of the extraction process"""
    
    total_threats: int = Field(
        description="Total number of threats identified",
        default=0
    )
    high_severity_count: int = Field(
        description="Number of high severity threats",
        default=0
    )
    technologies_identified: int = Field(
        description="Number of technologies identified",
        default=0
    )
    has_security_objectives: bool = Field(
        description="Whether security objectives were found",
        default=False
    )
    agent_based: bool = Field(
        description="Whether agent-based analysis was used",
        default=True
    )
    threat_source: str = Field(
        description="Source of threats: user_provided or ai_generated",
        default="ai_generated"
    )


class ExtractedInfo(BaseModel):
    """Complete extraction results"""
    
    threat_statements: List[Dict[str, Any]] = Field(
        description="All extracted threat statements",
        default_factory=list
    )
    high_severity_threats: List[Dict[str, Any]] = Field(
        description="High severity threats only",
        default_factory=list
    )
    project_info: ProjectInfo = Field(
        description="Project metadata and analysis",
        default_factory=ProjectInfo
    )
    extraction_summary: ExtractionSummary = Field(
        description="Summary of extraction process",
        default_factory=ExtractionSummary
    )
