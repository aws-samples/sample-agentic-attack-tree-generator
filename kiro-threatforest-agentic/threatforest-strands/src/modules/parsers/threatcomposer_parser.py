"""ThreatComposer format parser"""
import json
from pathlib import Path
from typing import Dict, Any
from .base import ThreatParser


class ThreatComposerParser(ThreatParser):
    """Parser for AWS ThreatComposer .tc files"""
    
    def __init__(self):
        super().__init__("threatcomposer")
    
    def can_parse(self, file_path: Path, content: str = None) -> bool:
        """Check if file is ThreatComposer format"""
        # Check for .tc or .tc.json extension
        if not (file_path.suffix.lower() == '.tc' or file_path.name.lower().endswith('.tc.json')):
            return False
        
        if content is None:
            try:
                content = file_path.read_text()
            except Exception:
                return False
        
        try:
            data = json.loads(content)
            # ThreatComposer files have specific structure
            return isinstance(data, dict) and ('threats' in data or 'architecture' in data)
        except json.JSONDecodeError:
            return False
    
    def parse(self, file_path: Path, content: str = None) -> Dict[str, Any]:
        """Parse ThreatComposer file"""
        if content is None:
            content = file_path.read_text()
        
        data = json.loads(content)
        
        # Extract threats from ThreatComposer structure
        threats = data.get('threats', [])
        architecture = data.get('architecture', {})
        
        return {
            "format": "threatcomposer",
            "file_path": str(file_path),
            "threats": threats,
            "architecture": architecture,
            "data": data
        }
