"""JSON threat model parser"""
import json
from pathlib import Path
from typing import Dict, Any
from .base import ThreatParser


class JSONThreatParser(ThreatParser):
    """Parser for JSON threat model files"""
    
    def __init__(self):
        super().__init__("json")
    
    def can_parse(self, file_path: Path, content: str = None) -> bool:
        """Check if file is JSON format"""
        if file_path.suffix.lower() not in ['.json', '.tc']:
            return False
        
        if content is None:
            try:
                content = file_path.read_text()
            except Exception:
                return False
        
        try:
            json.loads(content)
            return True
        except json.JSONDecodeError:
            return False
    
    def parse(self, file_path: Path, content: str = None) -> Dict[str, Any]:
        """Parse JSON threat model file"""
        if content is None:
            content = file_path.read_text()
        
        data = json.loads(content)
        
        return {
            "format": "json",
            "file_path": str(file_path),
            "data": data
        }
