"""Text parsing utilities for information extraction"""
import re
import json
from typing import Dict


def extract_field(text: str, field_name: str) -> str:
    """Extract a field value from markdown-style text
    
    Args:
        text: Text to search in
        field_name: Name of field to extract (e.g., 'Threat Source')
        
    Returns:
        Extracted field value or empty string
    """
    pattern = rf'\*\*{field_name}\*\*:\s*(.+?)(?:\n|$)'
    match = re.search(pattern, text)
    return match.group(1).strip() if match else ''


def find_threat_context(content: str, threat_description: str) -> str:
    """Find context around a threat statement to extract priority/category
    
    Args:
        content: Full file content
        threat_description: Threat description to find
        
    Returns:
        Context lines around the threat (5 before and after)
    """
    lines = content.split('\n')
    threat_line_idx = -1
    
    # Find the line containing the threat
    for i, line in enumerate(lines):
        if threat_description[:50] in line:
            threat_line_idx = i
            break
    
    if threat_line_idx >= 0:
        # Get context (5 lines before and after)
        start = max(0, threat_line_idx - 5)
        end = min(len(lines), threat_line_idx + 5)
        return '\n'.join(lines[start:end])
    
    return ""


def parse_json_response(content: str) -> dict:
    """Parse JSON response with markdown code block handling
    
    Handles various formats:
    - Plain JSON
    - JSON wrapped in markdown code blocks
    - JSON with extra text
    
    Args:
        content: Response content that may contain JSON
        
    Returns:
        Parsed JSON dict
        
    Raises:
        ValueError: If no valid JSON found
    """
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # Remove markdown code block markers
        cleaned_content = content.strip()
        if cleaned_content.startswith('```'):
            lines = cleaned_content.split('\n')
            # Remove first line (```json or ```)
            lines = lines[1:]
            # Remove last line if it's ```
            if lines and lines[-1].strip() == '```':
                lines = lines[:-1]
            cleaned_content = '\n'.join(lines).strip()
        
        # Try parsing the cleaned content
        try:
            return json.loads(cleaned_content)
        except json.JSONDecodeError:
            # Find JSON structure manually
            json_start = cleaned_content.find('{')
            if json_start == -1:
                raise ValueError("No JSON structure found in response")
            
            # Find matching closing brace
            brace_count = 0
            json_end = json_start
            for i, char in enumerate(cleaned_content[json_start:], json_start):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        json_end = i + 1
                        break
            
            json_str = cleaned_content[json_start:json_end]
            return json.loads(json_str)
