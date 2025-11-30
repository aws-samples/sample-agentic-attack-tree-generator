"""ThreatForest Core Framework - Active Modules Only

Legacy modules archived to archive_docs/legacy-core/ (see README.md there for details)
"""

# Active core modules (actually used in codebase)
from .base_agent import BaseAgent
from .context import Context
from .state import ThreatForestState, WorkflowStage
from .state_manager import StateManager
from .file_discovery import FileDiscovery, DiscoveredFiles
from .progress_events import ProgressEvent, ProgressEventType
from .progress_emitter import ProgressEmitter

__all__ = [
    # Base classes
    'BaseAgent',
    
    # Workflow state
    'Context',
    'ThreatForestState',
    'WorkflowStage',
    'StateManager',
    
    # File operations
    'FileDiscovery',
    'DiscoveredFiles',
    
    # Progress tracking
    'ProgressEvent',
    'ProgressEventType',
    'ProgressEmitter'
]
