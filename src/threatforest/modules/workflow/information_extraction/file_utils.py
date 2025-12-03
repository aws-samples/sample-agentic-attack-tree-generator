"""File operation utilities for information extraction"""
import re
from typing import Dict, Any
from pathlib import Path


def is_text_file(file_path: str) -> bool:
    """Check if file can be processed (text files, images, PDFs)
    
    Args:
        file_path: Path to file to check
        
    Returns:
        True if file can be processed
    """
    import os
    
    # Check file extension
    supported_extensions = {
        # Text files
        '.json', '.tc', '.yaml', '.yml', '.md', '.txt', '.csv',
        # Images for Bedrock analysis
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp',
        # Documents for Bedrock analysis
        '.pdf'
    }
    _, ext = os.path.splitext(file_path.lower())
    
    # Special handling for .tc.json files
    if file_path.lower().endswith('.tc.json'):
        return True
    
    if ext in supported_extensions:
        return True
        
    # For files without extension, try to detect if it's text
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            if not chunk:
                return True  # Empty file
            # Check if it's mostly text (no null bytes)
            return b'\x00' not in chunk
    except:
        return False


def is_binary_file(file_path: str) -> bool:
    """Check if file is binary (images, PDFs) that needs special handling
    
    Args:
        file_path: Path to file to check
        
    Returns:
        True if file is binary
    """
    import os
    
    binary_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.pdf'}
    _, ext = os.path.splitext(file_path.lower())
    return ext in binary_extensions


def is_correct_format(content: str) -> bool:
    """Check if the threat file already matches the correct format
    
    Args:
        content: File content to check
        
    Returns:
        True if file is correctly formatted
    """
    # Check for key format indicators
    format_indicators = [
        r'# Generated Threat Statements',  # Header
        r'## Application Context',         # Context section
        r'### High Priority Threats',      # Priority grouping
        r'#### T\d{3} - ',                # Standardized T### format (not UUID)
        r'\*\*Threat Statement\*\*:',      # Threat statement marker (with colon)
        r'- \*\*Threat Source\*\*:',       # Structured fields (with colon)
        r'- \*\*Priority\*\*:',            # Priority field (with colon)
    ]
    
    # File is in correct format if it has most of these indicators
    matches = sum(1 for pattern in format_indicators if re.search(pattern, content))
    return matches >= 5  # At least 5 out of 7 indicators present


def contains_threat_content(content: str) -> bool:
    """Check if content contains threat-related information but not proper statements
    
    Args:
        content: File content to check
        
    Returns:
        True if content seems threat-related
    """
    threat_indicators = [
        'threat', 'risk', 'vulnerability', 'attack', 'security',
        'malicious', 'unauthorized', 'breach', 'compromise',
        'confidentiality', 'integrity', 'availability'
    ]
    
    content_lower = content.lower()
    threat_count = sum(1 for indicator in threat_indicators if indicator in content_lower)
    
    # If it has multiple threat indicators, it's likely threat-related content
    return threat_count >= 3


def analyze_threat_file(threat_file_path: str) -> Dict[str, Any]:
    """Analyze a threat file to determine its format and content quality
    
    Args:
        threat_file_path: Path to threat file
        
    Returns:
        Dict with file analysis results
    """
    file_path = Path(threat_file_path)
    
    try:
        # Read file content
        with open(threat_file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if ThreatComposer file
        is_threatcomposer = file_path.name.lower().endswith('.tc.json')
        
        # Analyze format correctness
        is_correct_fmt = is_correct_format(content) if not is_threatcomposer else False
        
        # Count potential threats (rough estimate)
        threat_count = 0
        if is_threatcomposer:
            threat_count = content.count('"statement"')  # Rough count for TC files
        else:
            threat_count = len(re.findall(r'#### [A-Za-z0-9\-]+ - ', content))
        
        return {
            'path': threat_file_path,
            'filename': file_path.name,
            'content': content,
            'is_threatcomposer': is_threatcomposer,
            'is_correct_format': is_correct_fmt,
            'estimated_threat_count': threat_count,
            'file_size': len(content)
        }
        
    except Exception as e:
        return {
            'path': threat_file_path,
            'filename': file_path.name,
            'content': '',
            'is_threatcomposer': False,
            'is_correct_format': False,
            'estimated_threat_count': 0,
            'file_size': 0,
            'error': str(e)
        }
