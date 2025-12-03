"""Pydantic models for structured threat output"""
from pydantic import BaseModel, Field
from typing import List, Optional


class ThreatModel(BaseModel):
    """Individual threat extracted from threat file"""
    
    id: str = Field(
        description="Unique threat identifier (e.g., T001, T002, uuid)"
    )
    statement: str = Field(
        description="Full threat statement describing the threat"
    )
    priority: str = Field(
        description="Threat priority: High, Medium, or Low"
    )
    category: str = Field(
        description="Threat category (e.g., Authentication, Data Breach, Injection)",
        default="General"
    )
    threatSource: Optional[str] = Field(
        description="Who or what could execute this threat (e.g., 'external attacker', 'malicious user')",
        default=None
    )
    prerequisites: Optional[str] = Field(
        description="What the attacker needs to execute the threat (e.g., 'network access', 'valid credentials')",
        default=None
    )
    threatAction: Optional[str] = Field(
        description="What the attacker does (e.g., 'exploit weak authentication', 'inject malicious code')",
        default=None
    )
    threatImpact: Optional[str] = Field(
        description="Immediate impact of the threat (e.g., 'unauthorized access', 'data breach')",
        default=None
    )
    impactedGoal: Optional[str] = Field(
        description="CIA triad goal affected: confidentiality, integrity, or availability",
        default=None
    )
    impactedAssets: Optional[List[str]] = Field(
        description="List of assets affected by the threat",
        default=None
    )


class ThreatList(BaseModel):
    """Complete list of threats extracted from a threat file"""
    
    threats: List[ThreatModel] = Field(
        description="Array of threat objects extracted from the file"
    )
