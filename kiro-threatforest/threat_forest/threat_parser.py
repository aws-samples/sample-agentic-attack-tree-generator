"""
Threat statement parsing and filtering functionality.
"""

import json
import re
from typing import List, Dict, Any, Optional
from pathlib import Path

from .models import ThreatStatement
from .context_parser import ParsedContent
from .file_scanner import FileType
from .llm_client import LLMClient
from .exceptions import FileProcessingError, LLMError
from .utils import get_logger, sanitize_filename


class ThreatParser:
    """Parses and filters threat statements from context files."""
    
    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client
        self.logger = get_logger(__name__)
        
        # Severity keywords for detection
        self.severity_patterns = {
            'high': ['high', 'critical', 'severe', 'major'],
            'medium': ['medium', 'moderate', 'significant'],
            'low': ['low', 'minor', 'negligible', 'trivial']
        }
    
    def parse_threats(self, parsed_files: List[ParsedContent]) -> List[ThreatStatement]:
        """
        Parse threat statements from context files.
        
        Args:
            parsed_files: List of parsed content objects
            
        Returns:
            List of ThreatStatement objects
        """
        self.logger.info("Parsing threat statements from context files")
        
        all_threats = []
        
        # Find threat statement files
        threat_files = [f for f in parsed_files if f.file_type == FileType.THREAT_STATEMENTS]
        
        if not threat_files:
            self.logger.warning("No threat statement files found")
            return []
        
        for threat_file in threat_files:
            try:
                threats = self._parse_threat_file(threat_file)
                all_threats.extend(threats)
                self.logger.info(f"Parsed {len(threats)} threats from {threat_file.file_path.name}")
            except Exception as e:
                self.logger.error(f"Failed to parse threats from {threat_file.file_path}: {e}")
        
        self.logger.info(f"Total threats parsed: {len(all_threats)}")
        return all_threats
    
    def _parse_threat_file(self, threat_file: ParsedContent) -> List[ThreatStatement]:
        """Parse threats from a single file."""
        if threat_file.structured_data:
            # Handle structured data (JSON/YAML)
            return self._parse_structured_threats(threat_file)
        else:
            # Handle text-based threats
            return self._parse_text_threats(threat_file)
    
    def _parse_structured_threats(self, threat_file: ParsedContent) -> List[ThreatStatement]:
        """Parse threats from structured data (JSON/YAML)."""
        data = threat_file.structured_data
        threats = []
        
        # Handle ThreatComposer format
        if 'threats' in data:
            for i, threat_data in enumerate(data['threats']):
                threat = self._create_threat_from_dict(
                    threat_data, 
                    threat_file.file_path, 
                    i + 1
                )
                if threat:
                    threats.append(threat)
        
        # Handle other structured formats
        elif isinstance(data, list):
            for i, threat_data in enumerate(data):
                if isinstance(threat_data, dict):
                    threat = self._create_threat_from_dict(
                        threat_data, 
                        threat_file.file_path, 
                        i + 1
                    )
                    if threat:
                        threats.append(threat)
        
        # Handle single threat object
        elif isinstance(data, dict) and ('title' in data or 'description' in data):
            threat = self._create_threat_from_dict(data, threat_file.file_path, 1)
            if threat:
                threats.append(threat)
        
        return threats
    
    def _parse_text_threats(self, threat_file: ParsedContent) -> List[ThreatStatement]:
        """Parse threats from text content."""
        if self.llm_client:
            return self._parse_text_with_llm(threat_file)
        else:
            return self._parse_text_with_patterns(threat_file)
    
    def _parse_text_with_llm(self, threat_file: ParsedContent) -> List[ThreatStatement]:
        """Use LLM to parse threats from text."""
        try:
            prompt = self.llm_client.create_extraction_prompt(
                threat_file.content, 
                "threats"
            )
            
            response = self.llm_client.generate(prompt)
            
            if not self.llm_client.validate_response(response, "json"):
                self.logger.warning("LLM response is not valid JSON, falling back to pattern matching")
                return self._parse_text_with_patterns(threat_file)
            
            threat_data = json.loads(response.content)
            
            threats = []
            for i, threat_dict in enumerate(threat_data):
                threat = self._create_threat_from_dict(
                    threat_dict, 
                    threat_file.file_path, 
                    i + 1
                )
                if threat:
                    threats.append(threat)
            
            return threats
            
        except (LLMError, json.JSONDecodeError) as e:
            self.logger.warning(f"LLM parsing failed: {e}, falling back to pattern matching")
            return self._parse_text_with_patterns(threat_file)
    
    def _parse_text_with_patterns(self, threat_file: ParsedContent) -> List[ThreatStatement]:
        """Parse threats using pattern matching."""
        threats = []
        lines = threat_file.content.split('\n')
        
        current_threat = None
        threat_counter = 1
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines
            if not line:
                continue
            
            # Look for threat indicators
            if self._is_threat_line(line):
                # Save previous threat if exists
                if current_threat:
                    threats.append(current_threat)
                
                # Start new threat
                current_threat = ThreatStatement(
                    id=f"threat-{threat_counter:03d}",
                    title=self._extract_title(line),
                    description=line,
                    severity=self._detect_severity(line),
                    source_file=str(threat_file.file_path),
                    line_number=line_num
                )
                threat_counter += 1
            
            elif current_threat and line:
                # Continue building current threat description
                current_threat.description += " " + line
                
                # Update severity if found in continuation
                detected_severity = self._detect_severity(line)
                if detected_severity != 'unknown' and current_threat.severity == 'unknown':
                    current_threat.severity = detected_severity
        
        # Add last threat
        if current_threat:
            threats.append(current_threat)
        
        return threats
    
    def _create_threat_from_dict(self, threat_data: Dict[str, Any], file_path: Path, index: int) -> Optional[ThreatStatement]:
        """Create ThreatStatement from dictionary data."""
        try:
            # Extract basic information
            title = threat_data.get('title', threat_data.get('name', f'Threat {index}'))
            description = threat_data.get('description', threat_data.get('content', ''))
            
            # Extract severity
            severity = self._normalize_severity(
                threat_data.get('severity', 
                threat_data.get('priority', 
                threat_data.get('risk_level', 'unknown')))
            )
            
            # Generate ID
            threat_id = threat_data.get('id', f"threat-{index:03d}")
            if not threat_id.startswith('threat-'):
                threat_id = f"threat-{sanitize_filename(threat_id)}"
            
            return ThreatStatement(
                id=threat_id,
                title=title,
                description=description,
                severity=severity,
                category=threat_data.get('category', ''),
                impact=threat_data.get('impact', ''),
                likelihood=threat_data.get('likelihood', ''),
                source_file=str(file_path),
                line_number=0
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to create threat from data: {e}")
            return None
    
    def _is_threat_line(self, line: str) -> bool:
        """Check if line indicates start of a threat."""
        line_lower = line.lower()
        
        # Look for threat indicators
        threat_indicators = [
            'threat:', 'risk:', 'vulnerability:', 'attack:', 'exploit:',
            'threat -', 'risk -', 'vulnerability -', 'attack -', 'exploit -',
            '## threat', '### threat', '## risk', '### risk'
        ]
        
        return any(indicator in line_lower for indicator in threat_indicators)
    
    def _extract_title(self, line: str) -> str:
        """Extract title from threat line."""
        # Remove common prefixes
        prefixes = ['threat:', 'risk:', 'vulnerability:', 'attack:', 'exploit:', '#', '-', '*']
        
        title = line.strip()
        for prefix in prefixes:
            if title.lower().startswith(prefix.lower()):
                title = title[len(prefix):].strip()
        
        # Limit title length
        if len(title) > 100:
            title = title[:100] + "..."
        
        return title or "Untitled Threat"
    
    def _detect_severity(self, text: str) -> str:
        """Detect severity level from text."""
        text_lower = text.lower()
        
        for severity, keywords in self.severity_patterns.items():
            if any(keyword in text_lower for keyword in keywords):
                return severity
        
        return 'unknown'
    
    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity to standard values."""
        if not severity:
            return 'unknown'
        
        severity_lower = str(severity).lower().strip()
        
        # Map various severity formats to standard values
        severity_mapping = {
            'critical': 'high',
            'severe': 'high',
            'major': 'high',
            'important': 'high',
            '5': 'high',
            '4': 'high',
            
            'moderate': 'medium',
            'significant': 'medium',
            '3': 'medium',
            
            'minor': 'low',
            'negligible': 'low',
            'trivial': 'low',
            '2': 'low',
            '1': 'low'
        }
        
        return severity_mapping.get(severity_lower, severity_lower)
    
    def filter_high_severity_threats(self, threats: List[ThreatStatement]) -> List[ThreatStatement]:
        """
        Filter threats to only include high-severity ones.
        
        Args:
            threats: List of all threat statements
            
        Returns:
            List of high-severity threats only
        """
        high_threats = [t for t in threats if t.severity == 'high']
        
        self.logger.info(f"Filtered {len(high_threats)} high-severity threats from {len(threats)} total")
        
        if not high_threats:
            self.logger.warning("No high-severity threats found. Consider reviewing severity detection.")
        
        return high_threats
    
    def get_threat_summary(self, threats: List[ThreatStatement]) -> Dict[str, Any]:
        """
        Generate summary statistics for threats.
        
        Args:
            threats: List of threat statements
            
        Returns:
            Summary dictionary
        """
        if not threats:
            return {
                'total_threats': 0,
                'severity_distribution': {},
                'source_files': [],
                'categories': []
            }
        
        # Count by severity
        severity_counts = {}
        for threat in threats:
            severity = threat.severity or 'unknown'
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Get unique source files
        source_files = list(set(t.source_file for t in threats))
        
        # Get unique categories
        categories = list(set(t.category for t in threats if t.category))
        
        return {
            'total_threats': len(threats),
            'severity_distribution': severity_counts,
            'source_files': source_files,
            'categories': categories,
            'high_severity_count': severity_counts.get('high', 0)
        }