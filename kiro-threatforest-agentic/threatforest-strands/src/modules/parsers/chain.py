"""Parser chain for automatic format detection and parsing"""
from typing import List, Optional, Dict, Any
from pathlib import Path
from .base import ThreatParser


class ParserChain:
    """Chain of responsibility pattern for threat model parsing"""
    
    def __init__(self):
        self.parsers: List[ThreatParser] = []
    
    def register(self, parser: ThreatParser, priority: int = 0):
        """Register a parser with optional priority
        
        Args:
            parser: Parser instance to register
            priority: Priority level (higher = checked first)
        """
        self.parsers.append((priority, parser))
        # Sort by priority (descending)
        self.parsers.sort(key=lambda x: x[0], reverse=True)
    
    def parse(self, file_path: Path, content: str = None) -> Optional[Dict[str, Any]]:
        """Parse file using first compatible parser
        
        Args:
            file_path: Path to the file
            content: Optional file content
            
        Returns:
            Parsed data or None if no parser can handle it
        """
        # Read content if not provided
        if content is None and file_path.exists():
            content = file_path.read_text()
        
        # Try each parser in priority order
        for priority, parser in self.parsers:
            if parser.can_parse(file_path, content):
                return parser.parse(file_path, content)
        
        return None
    
    def get_compatible_parser(self, file_path: Path, content: str = None) -> Optional[ThreatParser]:
        """Get the first compatible parser for a file
        
        Args:
            file_path: Path to the file
            content: Optional file content
            
        Returns:
            Compatible parser or None
        """
        if content is None and file_path.exists():
            content = file_path.read_text()
        
        for priority, parser in self.parsers:
            if parser.can_parse(file_path, content):
                return parser
        
        return None
