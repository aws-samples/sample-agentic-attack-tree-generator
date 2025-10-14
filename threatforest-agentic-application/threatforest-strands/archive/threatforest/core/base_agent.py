"""Base Agent class for Strands framework implementation"""
from typing import Dict, List, Any, Callable
from functools import wraps
from .base_tool import Tool


class Agent:
    """Base class for Strands agents that orchestrate tools"""
    
    def __init__(self, name: str, description: str, tools: List[Tool] = None):
        self.name = name
        self.description = description
        self.tools = {tool.name: tool for tool in (tools or [])}
    
    async def use_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool by name with given parameters"""
        if tool_name not in self.tools:
            raise ValueError(f"Tool '{tool_name}' not found in agent '{self.name}'")
        
        tool = self.tools[tool_name]
        return await tool.execute(**params)
    
    def register_tool(self, tool: Tool):
        """Register a new tool with the agent"""
        self.tools[tool.name] = tool
    
    def __repr__(self) -> str:
        return f"Agent(name='{self.name}', tools={list(self.tools.keys())})"


def agent_step(dependencies: List[str] = None):
    """Decorator to mark a method as an agent workflow step"""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            return await func(self, *args, **kwargs)
        
        wrapper._is_agent_step = True
        wrapper._dependencies = dependencies or []
        return wrapper
    
    return decorator
