"""Base parser interface for threat model parsing"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List
from pathlib import Path


class ThreatParser(ABC):
    """Abstract base class for threat model parsers"""
    
    def __init__(self, name: str):
        self.name = name
    
    @abstractmethod
    def can_parse(self, file_path: Path, content: str = None) -> bool:
        """Check if this parser can handle the given file
        
        Args:
            file_path: Path to the file
            content: Optional file content (to avoid re-reading)
            
        Returns:
            True if parser can handle this file
        """
        pass
    
    @abstractmethod
    def parse(self, file_path: Path, content: str = None) -> Dict[str, Any]:
        """Parse the threat model file
        
        Args:
            file_path: Path to the file
            content: Optional file content (to avoid re-reading)
            
        Returns:
            Parsed threat model data
        """
        pass
