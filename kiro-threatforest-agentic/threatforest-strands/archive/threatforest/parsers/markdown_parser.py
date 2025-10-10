"""Markdown threat model parser"""
import re
from pathlib import Path
from typing import Dict, Any, List
from .base import ThreatParser


class MarkdownThreatParser(ThreatParser):
    """Parser for Markdown threat model files"""
    
    def __init__(self):
        super().__init__("markdown")
    
    def can_parse(self, file_path: Path, content: str = None) -> bool:
        """Check if file is Markdown format"""
        if file_path.suffix.lower() not in ['.md', '.markdown']:
            return False
        
        if content is None:
            try:
                content = file_path.read_text()
            except Exception:
                return False
        
        # Check for common threat model markdown patterns
        patterns = [
            r'#+\s*(threat|attack|risk|vulnerability)',
            r'\*\*threat\*\*',
            r'##\s*threats?',
        ]
        
        content_lower = content.lower()
        return any(re.search(pattern, content_lower, re.IGNORECASE) for pattern in patterns)
    
    def parse(self, file_path: Path, content: str = None) -> Dict[str, Any]:
        """Parse Markdown threat model file"""
        if content is None:
            content = file_path.read_text()
        
        threats = self._extract_threats(content)
        
        return {
            "format": "markdown",
            "file_path": str(file_path),
            "threats": threats,
            "raw_content": content
        }
    
    def _extract_threats(self, content: str) -> List[Dict[str, Any]]:
        """Extract threat information from markdown content"""
        threats = []
        
        # Split by headers
        sections = re.split(r'\n#+\s+', content)
        
        for section in sections:
            if not section.strip():
                continue
            
            # Check if section contains threat-related keywords
            section_lower = section.lower()
            if any(keyword in section_lower for keyword in ['threat', 'attack', 'risk', 'vulnerability']):
                lines = section.split('\n')
                title = lines[0].strip() if lines else "Unknown Threat"
                description = '\n'.join(lines[1:]).strip()
                
                threats.append({
                    "title": title,
                    "description": description,
                    "severity": self._extract_severity(section)
                })
        
        return threats
    
    def _extract_severity(self, text: str) -> str:
        """Extract severity from text"""
        text_lower = text.lower()
        if 'critical' in text_lower or 'high' in text_lower:
            return 'High'
        elif 'medium' in text_lower or 'moderate' in text_lower:
            return 'Medium'
        elif 'low' in text_lower:
            return 'Low'
        return 'Unknown'
