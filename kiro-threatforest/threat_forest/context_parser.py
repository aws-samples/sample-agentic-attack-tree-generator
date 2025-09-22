"""
Context file parsing functionality for ThreatForest.
"""

import json
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from .file_scanner import FileInfo, FileType
from .exceptions import FileProcessingError
from .utils import get_logger


@dataclass
class ParsedContent:
    """Container for parsed file content."""
    file_path: Path
    file_type: FileType
    content: str
    metadata: Dict[str, Any]
    structured_data: Optional[Dict[str, Any]] = None


class ContextParser:
    """Parses different types of context files."""
    
    def __init__(self):
        self.logger = get_logger(__name__)
    
    def parse_files(self, files: List[FileInfo]) -> List[ParsedContent]:
        """
        Parse a list of files and extract their content.
        
        Args:
            files: List of FileInfo objects to parse
            
        Returns:
            List of ParsedContent objects
        """
        parsed_files = []
        
        for file_info in files:
            try:
                parsed_content = self.parse_file(file_info)
                if parsed_content:
                    parsed_files.append(parsed_content)
                    self.logger.debug(f"Parsed {file_info.file_type.value}: {file_info.path.name}")
            except Exception as e:
                self.logger.error(f"Failed to parse {file_info.path}: {e}")
                # Continue with other files
        
        self.logger.info(f"Successfully parsed {len(parsed_files)} files")
        return parsed_files
    
    def parse_file(self, file_info: FileInfo) -> Optional[ParsedContent]:
        """
        Parse a single file based on its type and format.
        
        Args:
            file_info: FileInfo object describing the file
            
        Returns:
            ParsedContent object or None if parsing failed
        """
        if not file_info.is_readable:
            raise FileProcessingError(f"File is not readable: {file_info.path}")
        
        try:
            # Determine parsing method based on file extension
            suffix = file_info.path.suffix.lower()
            
            if suffix == '.json':
                return self._parse_json_file(file_info)
            elif suffix in ['.yaml', '.yml']:
                return self._parse_yaml_file(file_info)
            elif suffix in ['.md', '.txt', '.rst']:
                return self._parse_text_file(file_info)
            else:
                # Try to parse as text for unknown extensions
                return self._parse_text_file(file_info)
                
        except Exception as e:
            raise FileProcessingError(f"Error parsing {file_info.path}: {e}")
    
    def _parse_json_file(self, file_info: FileInfo) -> ParsedContent:
        """Parse JSON file."""
        try:
            with open(file_info.path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Convert JSON to readable text
            content = json.dumps(data, indent=2)
            
            # Extract metadata based on file type
            metadata = self._extract_json_metadata(data, file_info.file_type)
            
            return ParsedContent(
                file_path=file_info.path,
                file_type=file_info.file_type,
                content=content,
                metadata=metadata,
                structured_data=data
            )
            
        except json.JSONDecodeError as e:
            raise FileProcessingError(f"Invalid JSON in {file_info.path}: {e}")
    
    def _parse_yaml_file(self, file_info: FileInfo) -> ParsedContent:
        """Parse YAML file."""
        try:
            with open(file_info.path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            # Convert YAML to readable text
            content = yaml.dump(data, default_flow_style=False, indent=2)
            
            # Extract metadata
            metadata = self._extract_yaml_metadata(data, file_info.file_type)
            
            return ParsedContent(
                file_path=file_info.path,
                file_type=file_info.file_type,
                content=content,
                metadata=metadata,
                structured_data=data
            )
            
        except yaml.YAMLError as e:
            raise FileProcessingError(f"Invalid YAML in {file_info.path}: {e}")
    
    def _parse_text_file(self, file_info: FileInfo) -> ParsedContent:
        """Parse text-based file (Markdown, plain text, etc.)."""
        try:
            # Try different encodings
            encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']
            content = None
            
            for encoding in encodings:
                try:
                    with open(file_info.path, 'r', encoding=encoding) as f:
                        content = f.read()
                    break
                except UnicodeDecodeError:
                    continue
            
            if content is None:
                raise FileProcessingError(f"Could not decode file with any supported encoding")
            
            # Extract metadata based on content
            metadata = self._extract_text_metadata(content, file_info.file_type)
            
            return ParsedContent(
                file_path=file_info.path,
                file_type=file_info.file_type,
                content=content,
                metadata=metadata
            )
            
        except Exception as e:
            raise FileProcessingError(f"Error reading text file: {e}")
    
    def _extract_json_metadata(self, data: Dict[str, Any], file_type: FileType) -> Dict[str, Any]:
        """Extract metadata from JSON data."""
        metadata = {
            'format': 'json',
            'size': len(str(data))
        }
        
        if file_type == FileType.THREAT_STATEMENTS:
            # Handle ThreatComposer format
            if 'applicationInfo' in data:
                app_info = data['applicationInfo']
                metadata.update({
                    'application_name': app_info.get('name', ''),
                    'application_description': app_info.get('description', ''),
                    'has_threats': 'threats' in data or len(data.get('threats', [])) > 0
                })
            
            # Count threats if present
            if 'threats' in data:
                threats = data['threats']
                metadata['threat_count'] = len(threats)
                
                # Count by severity
                severity_counts = {}
                for threat in threats:
                    severity = threat.get('severity', 'unknown').lower()
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                metadata['severity_distribution'] = severity_counts
        
        return metadata
    
    def _extract_yaml_metadata(self, data: Dict[str, Any], file_type: FileType) -> Dict[str, Any]:
        """Extract metadata from YAML data."""
        metadata = {
            'format': 'yaml',
            'size': len(str(data))
        }
        
        # Add specific metadata based on content structure
        if isinstance(data, dict):
            metadata['top_level_keys'] = list(data.keys())
        
        return metadata
    
    def _extract_text_metadata(self, content: str, file_type: FileType) -> Dict[str, Any]:
        """Extract metadata from text content."""
        lines = content.split('\n')
        
        metadata = {
            'format': 'text',
            'size': len(content),
            'line_count': len(lines),
            'word_count': len(content.split())
        }
        
        if file_type == FileType.README:
            # Extract README-specific metadata
            metadata.update(self._analyze_readme_content(content))
        elif file_type == FileType.THREAT_STATEMENTS:
            # Extract threat-specific metadata
            metadata.update(self._analyze_threat_content(content))
        
        return metadata
    
    def _analyze_readme_content(self, content: str) -> Dict[str, Any]:
        """Analyze README content for key information."""
        metadata = {}
        
        # Look for common sections
        sections = []
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('#'):
                sections.append(line.lstrip('#').strip().lower())
        
        metadata['sections'] = sections
        
        # Look for technology mentions
        tech_keywords = [
            'python', 'java', 'javascript', 'typescript', 'go', 'rust', 'c++', 'c#',
            'react', 'vue', 'angular', 'django', 'flask', 'spring', 'express',
            'docker', 'kubernetes', 'aws', 'azure', 'gcp', 'terraform',
            'postgresql', 'mysql', 'mongodb', 'redis', 'elasticsearch'
        ]
        
        content_lower = content.lower()
        found_technologies = [tech for tech in tech_keywords if tech in content_lower]
        metadata['mentioned_technologies'] = found_technologies
        
        return metadata
    
    def _analyze_threat_content(self, content: str) -> Dict[str, Any]:
        """Analyze threat statement content."""
        metadata = {}
        
        # Count potential threat statements
        threat_indicators = ['threat', 'risk', 'vulnerability', 'attack', 'exploit']
        threat_count = 0
        
        for line in content.split('\n'):
            line_lower = line.lower()
            if any(indicator in line_lower for indicator in threat_indicators):
                threat_count += 1
        
        metadata['potential_threats'] = threat_count
        
        # Look for severity mentions
        severity_keywords = ['high', 'medium', 'low', 'critical', 'severe']
        found_severities = []
        
        for keyword in severity_keywords:
            if keyword in content.lower():
                found_severities.append(keyword)
        
        metadata['mentioned_severities'] = found_severities
        
        return metadata
    
    def combine_content(self, parsed_files: List[ParsedContent]) -> str:
        """
        Combine content from multiple files into a single context string.
        
        Args:
            parsed_files: List of parsed content objects
            
        Returns:
            Combined content string
        """
        combined_parts = []
        
        for parsed in parsed_files:
            header = f"\n=== {parsed.file_type.value.upper()}: {parsed.file_path.name} ===\n"
            combined_parts.append(header)
            combined_parts.append(parsed.content)
            combined_parts.append("\n")
        
        return "\n".join(combined_parts)
    
    def get_content_summary(self, parsed_files: List[ParsedContent]) -> Dict[str, Any]:
        """
        Generate a summary of all parsed content.
        
        Args:
            parsed_files: List of parsed content objects
            
        Returns:
            Summary dictionary
        """
        summary = {
            'total_files': len(parsed_files),
            'file_types': {},
            'total_size': 0,
            'technologies_mentioned': set(),
            'has_threat_data': False
        }
        
        for parsed in parsed_files:
            file_type = parsed.file_type.value
            summary['file_types'][file_type] = summary['file_types'].get(file_type, 0) + 1
            summary['total_size'] += parsed.metadata.get('size', 0)
            
            # Collect mentioned technologies
            if 'mentioned_technologies' in parsed.metadata:
                summary['technologies_mentioned'].update(parsed.metadata['mentioned_technologies'])
            
            # Check for threat data
            if parsed.file_type == FileType.THREAT_STATEMENTS:
                summary['has_threat_data'] = True
        
        # Convert set to list for JSON serialization
        summary['technologies_mentioned'] = list(summary['technologies_mentioned'])
        
        return summary