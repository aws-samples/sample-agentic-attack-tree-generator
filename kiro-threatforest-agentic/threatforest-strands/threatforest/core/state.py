"""State management models for ThreatForest workflow"""
from enum import Enum
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from pathlib import Path


class WorkflowStage(str, Enum):
    """Workflow stages for ThreatForest execution"""
    SETUP = "setup"
    CONTEXT_ANALYSIS = "context_analysis"
    EXTRACTION = "extraction"
    TREE_GENERATION = "tree_generation"
    MAPPING = "mapping"
    SUMMARY = "summary"
    COMPLETE = "complete"


class ThreatForestState(BaseModel):
    """State model for ThreatForest workflow execution"""
    
    # Workflow metadata
    current_stage: WorkflowStage = WorkflowStage.SETUP
    started_at: datetime = Field(default_factory=datetime.now)
    last_updated: datetime = Field(default_factory=datetime.now)
    
    # Configuration
    project_path: str
    aws_profile: Optional[str] = None
    bedrock_model: str
    
    # Stage completion flags
    setup_complete: bool = False
    context_complete: bool = False
    extraction_complete: bool = False
    tree_generation_complete: bool = False
    mapping_complete: bool = False
    summary_complete: bool = False
    
    # Stage results
    setup_result: Optional[Dict[str, Any]] = None
    context_files: Optional[Dict[str, Any]] = None
    extracted_info: Optional[Dict[str, Any]] = None
    attack_trees: List[Dict[str, Any]] = Field(default_factory=list)
    mapped_trees: List[Dict[str, Any]] = Field(default_factory=list)
    output_files: List[str] = Field(default_factory=list)
    
    # Error tracking
    errors: List[str] = Field(default_factory=list)
    
    class Config:
        use_enum_values = True
    
    def can_transition_to(self, stage: WorkflowStage) -> bool:
        """Validate if transition to new stage is allowed"""
        transitions = {
            WorkflowStage.SETUP: [],
            WorkflowStage.CONTEXT_ANALYSIS: [WorkflowStage.SETUP],
            WorkflowStage.EXTRACTION: [WorkflowStage.CONTEXT_ANALYSIS],
            WorkflowStage.TREE_GENERATION: [WorkflowStage.EXTRACTION],
            WorkflowStage.MAPPING: [WorkflowStage.TREE_GENERATION],
            WorkflowStage.SUMMARY: [WorkflowStage.MAPPING, WorkflowStage.TREE_GENERATION],
            WorkflowStage.COMPLETE: [WorkflowStage.SUMMARY]
        }
        
        required_stages = transitions.get(stage, [])
        return self.current_stage in required_stages or self.current_stage == stage
    
    def advance_to(self, stage: WorkflowStage):
        """Advance workflow to next stage with validation"""
        if not self.can_transition_to(stage):
            raise ValueError(
                f"Cannot transition from {self.current_stage} to {stage}"
            )
        self.current_stage = stage
        self.last_updated = datetime.now()
