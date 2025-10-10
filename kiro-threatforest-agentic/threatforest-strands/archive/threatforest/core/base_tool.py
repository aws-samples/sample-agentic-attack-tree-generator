"""Base Tool class for Strands framework implementation"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Callable
from functools import wraps


class Tool(ABC):
    """Base class for all Strands tools"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self._execute_func = None
    
    @abstractmethod
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute the tool with given parameters"""
        pass
    
    def __repr__(self) -> str:
        return f"Tool(name='{self.name}')"


def tool(name: str = None, description: str = None):
    """Decorator to mark a method as a tool execution point"""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(self, **kwargs):
            return await func(self, **kwargs)
        
        wrapper._is_tool = True
        wrapper._tool_name = name or func.__name__
        wrapper._tool_description = description or func.__doc__ or ""
        return wrapper
    
    return decorator
