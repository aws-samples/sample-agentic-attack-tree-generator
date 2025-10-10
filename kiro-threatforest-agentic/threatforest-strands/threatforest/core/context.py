"""Context class for managing workflow state"""
from typing import Dict, Any


class Context:
    """Manages state and data flow between tools and agents"""
    
    def __init__(self):
        self.data: Dict[str, Any] = {}
    
    def add(self, key: str, value: Any):
        """Add data to context"""
        self.data[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get data from context"""
        return self.data.get(key, default)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary"""
        return self.data.copy()
    
    def __repr__(self) -> str:
        return f"Context(keys={list(self.data.keys())})"
