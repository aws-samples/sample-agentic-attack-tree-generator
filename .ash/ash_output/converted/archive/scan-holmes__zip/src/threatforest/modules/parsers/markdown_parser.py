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
        
        # Split by level 4 headers (####) which contain threat IDs
        sections = re.split(r'\n####\s+', content)
        
        for section in sections[1:]:  # Skip first section (before any #### headers)
            if not section.strip():
                continue
            
            lines = section.split('\n')
            title = lines[0].strip() if lines else "Unknown Threat"
            
            # Only process sections that start with threat ID pattern (T### - Category)
            if not re.match(r'T\d+\s*-\s*\w+', title):
                continue
            
            description = '\n'.join(lines[1:]).strip()
            
            # Extract threat ID
            threat_id_match = re.match(r'(T\d+)', title)
            threat_id = threat_id_match.group(1) if threat_id_match else "Unknown"
            
            # Extract category from title (T001 - Authentication -> Authentication)
            category_match = re.match(r'T\d+\s*-\s*(.+)', title)
            category = category_match.group(1).strip() if category_match else "Unknown"
            
            threats.append({
                "id": threat_id,
                "title": title,
                "category": category,
                "description": description,
                "severity": self._extract_severity(section)
            })
        
        return threats
    
    def _extract_severity(self, text: str) -> str:
        """Extract severity from Priority field in text"""
        # Look for Priority field specifically
        priority_match = re.search(r'-\s*\*\*Priority\*\*:\s*(\w+)', text, re.IGNORECASE)
        if priority_match:
            priority = priority_match.group(1).strip()
            return priority.capitalize()
        
        # Fallback to general text search
        text_lower = text.lower()
        if 'priority: high' in text_lower or 'priority:high' in text_lower:
            return 'High'
        elif 'priority: medium' in text_lower or 'priority:medium' in text_lower:
            return 'Medium'
        elif 'priority: low' in text_lower or 'priority:low' in text_lower:
            return 'Low'
        return 'Unknown'
