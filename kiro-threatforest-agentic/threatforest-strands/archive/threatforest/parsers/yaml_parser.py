"""YAML threat model parser"""
import yaml
from pathlib import Path
from typing import Dict, Any
from .base import ThreatParser


class YAMLThreatParser(ThreatParser):
    """Parser for YAML threat model files"""
    
    def __init__(self):
        super().__init__("yaml")
    
    def can_parse(self, file_path: Path, content: str = None) -> bool:
        """Check if file is YAML format"""
        if file_path.suffix.lower() not in ['.yaml', '.yml']:
            return False
        
        if content is None:
            try:
                content = file_path.read_text()
            except Exception:
                return False
        
        try:
            yaml.safe_load(content)
            return True
        except yaml.YAMLError:
            return False
    
    def parse(self, file_path: Path, content: str = None) -> Dict[str, Any]:
        """Parse YAML threat model file"""
        if content is None:
            content = file_path.read_text()
        
        data = yaml.safe_load(content)
        
        return {
            "format": "yaml",
            "file_path": str(file_path),
            "data": data
        }
