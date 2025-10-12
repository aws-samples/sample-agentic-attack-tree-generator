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
    started_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    last_updated: str = Field(default_factory=lambda: datetime.now().isoformat())
    
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
        self.last_updated = datetime.now().isoformat()
    
    def is_valid_for_resume(self) -> tuple[bool, str]:
        """Validate if state is valid for resuming workflow"""
        # Check if workflow is already complete
        if self.current_stage == WorkflowStage.COMPLETE.value:
            return False, "Workflow already complete"
        
        # Define stage order for comparison
        stage_order = {
            WorkflowStage.SETUP.value: 0,
            WorkflowStage.CONTEXT_ANALYSIS.value: 1,
            WorkflowStage.EXTRACTION.value: 2,
            WorkflowStage.TREE_GENERATION.value: 3,
            WorkflowStage.MAPPING.value: 4,
            WorkflowStage.SUMMARY.value: 5,
            WorkflowStage.COMPLETE.value: 6
        }
        
        current_order = stage_order.get(self.current_stage, 0)
        
        # Validate stage completion consistency
        stage_checks = [
            (WorkflowStage.CONTEXT_ANALYSIS.value, self.setup_complete, "Setup incomplete"),
            (WorkflowStage.EXTRACTION.value, self.context_complete, "Context analysis incomplete"),
            (WorkflowStage.TREE_GENERATION.value, self.extraction_complete, "Extraction incomplete"),
            (WorkflowStage.MAPPING.value, self.tree_generation_complete, "Tree generation incomplete"),
            (WorkflowStage.SUMMARY.value, self.tree_generation_complete, "Tree generation incomplete"),
        ]
        
        for stage, required_flag, error_msg in stage_checks:
            stage_order_val = stage_order.get(stage, 0)
            if current_order >= stage_order_val and not required_flag:
                return False, f"Invalid state: {error_msg} for stage {self.current_stage}"
        
        return True, "State valid for resume"
