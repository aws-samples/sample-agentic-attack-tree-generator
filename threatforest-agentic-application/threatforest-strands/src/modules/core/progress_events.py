"""Progress event models for real-time workflow updates"""
from enum import Enum
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class ProgressEventType(str, Enum):
    """Types of progress events"""
    STAGE_START = "stage_start"
    STAGE_PROGRESS = "stage_progress"
    STAGE_COMPLETE = "stage_complete"
    THREAT_START = "threat_start"
    THREAT_COMPLETE = "threat_complete"
    ERROR = "error"
    WARNING = "warning"


class ProgressEvent(BaseModel):
    """Progress event emitted during workflow execution"""
    type: ProgressEventType
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    stage: str  # WorkflowStage value
    percentage: float = Field(ge=0.0, le=100.0)
    message: str
    details: Optional[Dict[str, Any]] = None
    
    class Config:
        use_enum_values = True
