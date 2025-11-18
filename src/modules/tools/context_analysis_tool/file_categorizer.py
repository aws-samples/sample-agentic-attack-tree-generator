"""File categorization utilities"""
from pathlib import Path
from typing import Dict, List


class FileCategorizer:
    """Categorizes project files by type"""
    
    def __init__(self, logger):
        self.logger = logger
        self.threat_keywords = ['threat', 'risk', 'vulnerability', 'attack', 'security']
    
    def contains_threat_statements(self, file_path: Path) -> bool:
        """Check if a file contains threat statements"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().lower()
            
            # Look for threat statement indicators
            threat_indicators = [
                "threat statement", "threat description", "threat source",
                "threat action", "threat impact", "high priority", "medium priority",
                "low priority", "severity", "can perform", "which leads to", "resulting in"
            ]
            
            # Check if file contains multiple threat indicators
            indicator_count = sum(1 for indicator in threat_indicators if indicator in content)
            return indicator_count >= 3
            
        except Exception as e:
            self.logger.warning(f"Could not read file {file_path}: {e}")
            return False
    
    @staticmethod
    def is_text_file(file_path: str) -> bool:
        """Check if file can be processed"""
        import os
        supported_extensions = {
            '.json', '.tc', '.yaml', '.yml', '.md', '.txt', '.csv',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.pdf'
        }
        _, ext = os.path.splitext(file_path.lower())
        
        if ext in supported_extensions:
            return True
        
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                if not chunk:
                    return True
                return b'\x00' not in chunk
        except:
            return False
    
    @staticmethod
    def is_binary_file(file_path: str) -> bool:
        """Check if file is binary"""
        import os
        binary_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.pdf'}
        _, ext = os.path.splitext(file_path.lower())
        return ext in binary_extensions
