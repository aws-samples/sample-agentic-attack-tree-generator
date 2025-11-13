"""Parallel execution utilities for ThreatForest workflow"""
import asyncio
from typing import List, Dict, Any, Callable, Awaitable
from dataclasses import dataclass


@dataclass
class ParallelTask:
    """Represents a task that can be executed in parallel"""
    name: str
    func: Callable[..., Awaitable[Any]]
    args: Dict[str, Any]


class ParallelExecutor:
    """Executes multiple tasks in parallel with concurrency control"""
    
    def __init__(self, max_concurrent: int = 3):
        self.max_concurrent = max_concurrent
    
    async def execute(self, tasks: List[ParallelTask]) -> Dict[str, Any]:
        """Execute tasks in parallel with concurrency limit"""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def run_task(task: ParallelTask):
            async with semaphore:
                try:
                    result = await task.func(**task.args)
                    return task.name, {"status": "success", "result": result}
                except Exception as e:
                    return task.name, {"status": "error", "error": str(e)}
        
        results = await asyncio.gather(*[run_task(task) for task in tasks])
        return dict(results)
