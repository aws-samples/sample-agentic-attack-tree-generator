"""Context class for managing workflow state"""
from typing import Dict, Any
from pathlib import Path


class Context:
    """Manages state and data flow between workflows and agents"""
    
    def __init__(self):
        self.data: Dict[str, Any] = {}
    
    def add(self, key: str, value: Any):
        """Add data to context"""
        self.data[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get data from context"""
        return self.data.get(key, default)
    
    def _convert_paths(self, obj: Any) -> Any:
        """Recursively convert Path objects to strings"""
        if isinstance(obj, Path):
            return str(obj)
        elif isinstance(obj, dict):
            return {k: self._convert_paths(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_paths(item) for item in obj]
        return obj
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary, converting Path objects to strings"""
        return self._convert_paths(self.data.copy())
    
    def __repr__(self) -> str:
        return f"Context(keys={list(self.data.keys())})"
