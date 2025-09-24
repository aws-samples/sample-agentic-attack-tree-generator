"""
Context Detection Agent for ThreatForest.

This agent scans directories for relevant context files including README files,
architecture diagrams, data flow diagrams, and threat statements. It validates
file formats and categorizes content for further processing.
"""

import os
import re
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum

from ..config import FileConfig


logger = logging.getLogger(__name__)


class FileType(str, Enum):
    """Enumeration for detected file types."""
    README = "readme"
    ARCHITECTURE_DIAGRAM = "architecture_diagram"
    DATA_FLOW_DIAGRAM = "data_flow_diagram"
    THREAT_STATEMENT = "threat_statement"
    CONFIGURATION = "configuration"
    DOCUMENTATION = "documentation"
    UNKNOWN = "unknown"


class FileFormat(str, Enum):
    """Enumeration for file formats."""
    MARKDOWN = "markdown"
    TEXT = "text"
    JSON = "json"
    YAML = "yaml"
    PNG = "png"
    SVG = "svg"
    MERMAID = "mermaid"
    PDF = "pdf"
    UNKNOWN = "unknown"


@dataclass
class DetectedFile:
    """Information about a detected context file."""
    
    path: Path
    file_type: FileType
    file_format: FileFormat
    size_bytes: int
    confidence_score: float
    metadata: Dict[str, Any]
    validation_errors: List[str]
    
    def is_valid(self) -> bool:
        """Check if the file is valid for processing."""
        return len(self.validation_errors) == 0 and self.confidence_score > 0.5
    
    def is_readable(self) -> bool:
        """Check if the file is readable."""
        return self.path.exists() and self.path.is_file() and os.access(self.path, os.R_OK)


@dataclass
class ContextScanResult:
    """Result of context directory scanning."""
    
    directory: Path
    detected_files: List[DetectedFile]
    scan_patterns: List[str]
    total_files_scanned: int
    processing_errors: List[str]
    
    def get_files_by_type(self, file_type: FileType) -> List[DetectedFile]:
        """Get all detected files of a specific type."""
        return [f for f in self.detected_files if f.file_type == file_type]
    
    def get_valid_files(self) -> List[DetectedFile]:
        """Get all valid files for processing."""
        return [f for f in self.detected_files if f.is_valid()]
    
    def has_required_files(self) -> bool:
        """Check if required file types are present."""
        file_types = {f.file_type for f in self.get_valid_files()}
        # At least one README or threat statement should be present
        return FileType.README in file_types or FileType.THREAT_STATEMENT in file_types


class ContextDetectionAgent:
    """
    Agent responsible for detecting and validating context files.
    
    Scans directories for relevant files, categorizes them by type and format,
    and validates their content for further processing by other agents.
    """
    
    def __init__(self, config: FileConfig):
        """
        Initialize the Context Detection Agent.
        
        Args:
            config: File processing configuration
        """
        self.config = config
        
        # File type detection patterns
        self.readme_patterns = [
            r'readme.*\.(md|txt|rst)$',
            r'readme$',
        ]
        
        self.architecture_patterns = [
            r'.*architecture.*\.(png|svg|jpg|jpeg|pdf|mmd)$',
            r'.*arch.*\.(png|svg|jpg|jpeg|pdf|mmd)$',
            r'.*system.*design.*\.(png|svg|jpg|jpeg|pdf|mmd)$',
        ]
        
        self.dataflow_patterns = [
            r'.*dataflow.*\.(png|svg|jpg|jpeg|pdf|mmd|md)$',
            r'.*data.*flow.*\.(png|svg|jpg|jpeg|pdf|mmd|md)$',
            r'.*dfd.*\.(png|svg|jpg|jpeg|pdf|mmd|md)$',
        ]
        
        self.threat_patterns = [
            r'threat.*\.(md|json|yaml|yml)$',
            r'.*threat.*\.(md|json|yaml|yml)$',
            r'security.*\.(md|json|yaml|yml)$',
            r'.*security.*\.(md|json|yaml|yml)$',
        ]
        
        # Content keywords for validation
        self.architecture_keywords = [
            'architecture', 'system', 'component', 'service', 'database',
            'api', 'microservice', 'infrastructure', 'deployment'
        ]
        
        self.dataflow_keywords = [
            'data flow', 'dataflow', 'process', 'input', 'output',
            'transformation', 'pipeline', 'workflow'
        ]
        
        self.threat_keywords = [
            'threat', 'risk', 'vulnerability', 'attack', 'security',
            'malicious', 'adversary', 'exploit', 'mitigation'
        ]
    
    def scan_directory(self, directory_path: str) -> ContextScanResult:
        """
        Scan a directory for context files.
        
        Args:
            directory_path: Path to directory to scan
            
        Returns:
            ContextScanResult with detected files and metadata
        """
        directory = Path(directory_path).resolve()
        
        if not directory.exists() or not directory.is_dir():
            raise ValueError(f"Directory does not exist or is not a directory: {directory}")
        
        logger.info(f"Scanning directory for context files: {directory}")
        
        detected_files = []
        processing_errors = []
        total_files_scanned = 0
        
        try:
            # Get all files matching the configured patterns
            all_files = self._get_matching_files(directory)
            total_files_scanned = len(all_files)
            
            logger.info(f"Found {total_files_scanned} files matching patterns")
            
            # Process each file
            for file_path in all_files:
                try:
                    detected_file = self._analyze_file(file_path)
                    if detected_file:
                        detected_files.append(detected_file)
                        logger.debug(f"Detected {detected_file.file_type} file: {file_path.name}")
                
                except Exception as e:
                    error_msg = f"Error analyzing file {file_path}: {e}"
                    logger.warning(error_msg)
                    processing_errors.append(error_msg)
            
            logger.info(f"Successfully detected {len(detected_files)} context files")
            
        except Exception as e:
            error_msg = f"Error scanning directory {directory}: {e}"
            logger.error(error_msg)
            processing_errors.append(error_msg)
        
        return ContextScanResult(
            directory=directory,
            detected_files=detected_files,
            scan_patterns=self.config.context_patterns,
            total_files_scanned=total_files_scanned,
            processing_errors=processing_errors
        )
    
    def _get_matching_files(self, directory: Path) -> List[Path]:
        """Get all files matching the configured patterns."""
        matching_files = set()
        
        for pattern in self.config.context_patterns:
            try:
                # Use glob to find matching files
                matches = list(directory.glob(pattern))
                # Also search in subdirectories (one level deep)
                matches.extend(directory.glob(f"*/{pattern}"))
                
                # Filter to only include files (not directories)
                file_matches = [f for f in matches if f.is_file()]
                matching_files.update(file_matches)
                
            except Exception as e:
                logger.warning(f"Error processing pattern '{pattern}': {e}")
        
        return list(matching_files)
    
    def _analyze_file(self, file_path: Path) -> Optional[DetectedFile]:
        """
        Analyze a single file to determine its type and validity.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            DetectedFile instance or None if file should be ignored
        """
        if not file_path.exists() or not file_path.is_file():
            return None
        
        # Get basic file information
        try:
            size_bytes = file_path.stat().st_size
        except OSError:
            size_bytes = 0
        
        # Skip empty files
        if size_bytes == 0:
            return None
        
        # Skip very large files (>10MB)
        if size_bytes > 10 * 1024 * 1024:
            return None
        
        # Determine file format
        file_format = self._detect_file_format(file_path)
        
        # Determine file type and confidence
        file_type, confidence_score, metadata = self._classify_file(file_path, file_format)
        
        # Validate file content
        validation_errors = self._validate_file(file_path, file_type, file_format)
        
        return DetectedFile(
            path=file_path,
            file_type=file_type,
            file_format=file_format,
            size_bytes=size_bytes,
            confidence_score=confidence_score,
            metadata=metadata,
            validation_errors=validation_errors
        )
    
    def _detect_file_format(self, file_path: Path) -> FileFormat:
        """Detect the format of a file based on extension and content."""
        extension = file_path.suffix.lower()
        
        format_map = {
            '.md': FileFormat.MARKDOWN,
            '.markdown': FileFormat.MARKDOWN,
            '.txt': FileFormat.TEXT,
            '.json': FileFormat.JSON,
            '.yaml': FileFormat.YAML,
            '.yml': FileFormat.YAML,
            '.png': FileFormat.PNG,
            '.svg': FileFormat.SVG,
            '.mmd': FileFormat.MERMAID,
            '.pdf': FileFormat.PDF,
        }
        
        return format_map.get(extension, FileFormat.UNKNOWN)
    
    def _classify_file(self, file_path: Path, file_format: FileFormat) -> Tuple[FileType, float, Dict[str, Any]]:
        """
        Classify a file by type and calculate confidence score.
        
        Returns:
            Tuple of (file_type, confidence_score, metadata)
        """
        filename = file_path.name.lower()
        metadata = {}
        
        # Check README patterns
        if any(re.match(pattern, filename, re.IGNORECASE) for pattern in self.readme_patterns):
            confidence = 0.9 if 'readme' in filename else 0.7
            return FileType.README, confidence, metadata
        
        # Check architecture patterns
        if any(re.match(pattern, filename, re.IGNORECASE) for pattern in self.architecture_patterns):
            confidence = self._calculate_content_confidence(file_path, self.architecture_keywords)
            return FileType.ARCHITECTURE_DIAGRAM, confidence, metadata
        
        # Check data flow patterns
        if any(re.match(pattern, filename, re.IGNORECASE) for pattern in self.dataflow_patterns):
            confidence = self._calculate_content_confidence(file_path, self.dataflow_keywords)
            return FileType.DATA_FLOW_DIAGRAM, confidence, metadata
        
        # Check threat patterns
        if any(re.match(pattern, filename, re.IGNORECASE) for pattern in self.threat_patterns):
            confidence = self._calculate_content_confidence(file_path, self.threat_keywords)
            return FileType.THREAT_STATEMENT, confidence, metadata
        
        # Default classification based on content
        if file_format in [FileFormat.MARKDOWN, FileFormat.TEXT]:
            # Try to classify based on content
            content_type, confidence = self._classify_by_content(file_path)
            return content_type, confidence, metadata
        
        return FileType.UNKNOWN, 0.1, metadata
    
    def _calculate_content_confidence(self, file_path: Path, keywords: List[str]) -> float:
        """Calculate confidence score based on content keywords."""
        if file_path.suffix.lower() in ['.png', '.jpg', '.jpeg', '.pdf', '.svg']:
            # For binary files, rely on filename matching
            return 0.8
        
        try:
            # Read text content
            content = self._read_text_content(file_path)
            if not content:
                return 0.3
            
            content_lower = content.lower()
            keyword_matches = sum(1 for keyword in keywords if keyword in content_lower)
            
            # Calculate confidence based on keyword density
            confidence = min(0.9, 0.5 + (keyword_matches * 0.1))
            return confidence
            
        except Exception:
            return 0.3
    
    def _classify_by_content(self, file_path: Path) -> Tuple[FileType, float]:
        """Classify file type based on content analysis."""
        try:
            content = self._read_text_content(file_path)
            if not content:
                return FileType.UNKNOWN, 0.1
            
            content_lower = content.lower()
            
            # Count keyword matches for each type
            arch_matches = sum(1 for keyword in self.architecture_keywords if keyword in content_lower)
            dataflow_matches = sum(1 for keyword in self.dataflow_keywords if keyword in content_lower)
            threat_matches = sum(1 for keyword in self.threat_keywords if keyword in content_lower)
            
            # Determine best match
            max_matches = max(arch_matches, dataflow_matches, threat_matches)
            
            if max_matches == 0:
                return FileType.DOCUMENTATION, 0.3
            
            confidence = min(0.8, 0.4 + (max_matches * 0.1))
            
            if arch_matches == max_matches:
                return FileType.ARCHITECTURE_DIAGRAM, confidence
            elif dataflow_matches == max_matches:
                return FileType.DATA_FLOW_DIAGRAM, confidence
            elif threat_matches == max_matches:
                return FileType.THREAT_STATEMENT, confidence
            
            return FileType.DOCUMENTATION, confidence
            
        except Exception:
            return FileType.UNKNOWN, 0.1
    
    def _read_text_content(self, file_path: Path, max_size: int = 1024 * 1024) -> str:
        """Safely read text content from a file."""
        try:
            if file_path.stat().st_size > max_size:
                # Read only first part of large files
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read(max_size)
            else:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
        except Exception:
            return ""
    
    def _validate_file(self, file_path: Path, file_type: FileType, file_format: FileFormat) -> List[str]:
        """
        Validate file content and structure.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Check file accessibility
        if not os.access(file_path, os.R_OK):
            errors.append("File is not readable")
            return errors
        
        # Format-specific validation
        if file_format == FileFormat.JSON:
            errors.extend(self._validate_json_file(file_path))
        elif file_format == FileFormat.YAML:
            errors.extend(self._validate_yaml_file(file_path))
        elif file_format in [FileFormat.MARKDOWN, FileFormat.TEXT]:
            errors.extend(self._validate_text_file(file_path))
        
        # Type-specific validation
        if file_type == FileType.THREAT_STATEMENT:
            errors.extend(self._validate_threat_file(file_path, file_format))
        
        return errors
    
    def _validate_json_file(self, file_path: Path) -> List[str]:
        """Validate JSON file structure."""
        errors = []
        try:
            import json
            with open(file_path, 'r', encoding='utf-8') as f:
                json.load(f)
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON format: {e}")
        except Exception as e:
            errors.append(f"Error reading JSON file: {e}")
        
        return errors
    
    def _validate_yaml_file(self, file_path: Path) -> List[str]:
        """Validate YAML file structure."""
        errors = []
        try:
            import yaml
            with open(file_path, 'r', encoding='utf-8') as f:
                yaml.safe_load(f)
        except yaml.YAMLError as e:
            errors.append(f"Invalid YAML format: {e}")
        except Exception as e:
            errors.append(f"Error reading YAML file: {e}")
        
        return errors
    
    def _validate_text_file(self, file_path: Path) -> List[str]:
        """Validate text/markdown file content."""
        errors = []
        
        try:
            content = self._read_text_content(file_path)
            
            # Check for minimum content length
            if len(content.strip()) < 10:
                errors.append("File content is too short")
            
            # Check for reasonable text content (not binary)
            if len(content) > 0:
                # Count printable characters
                printable_ratio = sum(1 for c in content[:1000] if c.isprintable() or c.isspace()) / min(len(content), 1000)
                if printable_ratio < 0.8:
                    errors.append("File appears to contain binary data")
        
        except Exception as e:
            errors.append(f"Error validating text content: {e}")
        
        return errors
    
    def _validate_threat_file(self, file_path: Path, file_format: FileFormat) -> List[str]:
        """Validate threat statement file content."""
        errors = []
        
        try:
            content = self._read_text_content(file_path)
            
            # Check for threat-related content
            threat_indicators = ['threat', 'risk', 'attack', 'vulnerability', 'security']
            if not any(indicator in content.lower() for indicator in threat_indicators):
                errors.append("File does not appear to contain threat-related content")
            
            # For JSON files, check for expected structure
            if file_format == FileFormat.JSON:
                import json
                try:
                    data = json.loads(content)
                    if isinstance(data, list):
                        # Check if it looks like a threat list
                        for item in data[:5]:  # Check first 5 items
                            if not isinstance(item, dict):
                                errors.append("JSON threat file should contain objects")
                                break
                    elif isinstance(data, dict):
                        # Single threat object - check for common fields
                        expected_fields = ['id', 'threat', 'impact', 'severity']
                        if not any(field in data for field in expected_fields):
                            errors.append("JSON threat object missing expected fields")
                except json.JSONDecodeError:
                    pass  # Already handled in JSON validation
        
        except Exception as e:
            errors.append(f"Error validating threat content: {e}")
        
        return errors