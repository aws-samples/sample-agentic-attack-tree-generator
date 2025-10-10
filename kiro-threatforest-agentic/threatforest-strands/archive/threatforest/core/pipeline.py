"""Pipeline orchestration for ThreatForest workflow stages"""
from typing import List, Dict, Any, Callable, Awaitable, Optional
from dataclasses import dataclass
from .state import WorkflowStage
from .parallel import ParallelExecutor, ParallelTask


@dataclass
class Stage:
    """Represents a workflow stage"""
    name: str
    stage_type: WorkflowStage
    execute_fn: Callable[..., Awaitable[Dict[str, Any]]]
    dependencies: List[WorkflowStage]
    can_parallelize: bool = False


class Pipeline:
    """Orchestrates workflow stages with dependency management"""
    
    def __init__(self):
        self.stages: List[Stage] = []
        self.parallel_executor = ParallelExecutor(max_concurrent=3)
    
    def add_stage(self, stage: Stage):
        """Add a stage to the pipeline"""
        self.stages.append(stage)
    
    def validate_dependencies(self) -> bool:
        """Validate that all stage dependencies are satisfied"""
        stage_types = {s.stage_type for s in self.stages}
        
        for stage in self.stages:
            for dep in stage.dependencies:
                if dep not in stage_types:
                    return False
        return True
    
    async def execute_stage(self, stage: Stage, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single stage"""
        return await stage.execute_fn(**context)
    
    def get_next_stages(self, completed: List[WorkflowStage]) -> List[Stage]:
        """Get stages that can be executed based on completed stages"""
        ready = []
        for stage in self.stages:
            if stage.stage_type in completed:
                continue
            if all(dep in completed for dep in stage.dependencies):
                ready.append(stage)
        return ready
