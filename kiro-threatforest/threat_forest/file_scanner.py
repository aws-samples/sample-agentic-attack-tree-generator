"""
File discovery and scanning functionality for ThreatForest.
"""

import os
import mimetypes
from pathlib import Path
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
from enum import Enum

from .exceptions import FileProcessingError
from .utils import get_logger


class FileType(Enum):
    """Enumeration of supported file types."""
    README = "readme"
    ARCHITECTURE_DIAGRAM = "architecture_diagram"
    DATA_FLOW_DIAGRAM = "data_flow_diagram"
    THREAT_STATEMENTS = "threat_statements"
    UNKNOWN = "unknown"


@dataclass
class FileInfo:
    """Information about a discovered file."""
    path: Path
    file_type: FileType
    size: int
    is_readable: bool
    mime_type: Optional[str] = None
    encoding: Optional[str] = None


@dataclass
class ScanResult:
    """Result of directory scanning operation."""
    input_directory: Path
    files_found: List[FileInfo]
    missing_file_types: Set[FileType]
    scan_errors: List[str]
    
    @property
    def has_required_files(self) -> bool:
        """Check if all required file types are present."""
        found_types = {f.file_type for f in self.files_found}
        required_types = {
            FileType.README,
            FileType.THREAT_STATEMENTS
        }
        return required_types.issubset(found_types)
    
    @property
    def readme_files(self) -> List[FileInfo]:
        """Get all README files."""
        return [f for f in self.files_found if f.file_type == FileType.README]
    
    @property
    def threat_statement_files(self) -> List[FileInfo]:
        """Get all threat statement files."""
        return [f for f in self.files_found if f.file_type == FileType.THREAT_STATEMENTS]
    
    @property
    def architecture_diagram_files(self) -> List[FileInfo]:
        """Get all architecture diagram files."""
        return [f for f in self.files_found if f.file_type == FileType.ARCHITECTURE_DIAGRAM]
    
    @property
    def data_flow_diagram_files(self) -> List[FileInfo]:
        """Get all data flow diagram files."""
        return [f for f in self.files_found if f.file_type == FileType.DATA_FLOW_DIAGRAM]


class FileScanner:
    """Scans directories for context files needed by ThreatForest."""
    
    # File patterns for different types
    README_PATTERNS = {
        "readme.md", "readme.txt", "readme.rst", "readme",
        "README.md", "README.txt", "README.rst", "README"
    }
    
    ARCHITECTURE_PATTERNS = {
        "architecture", "arch", "system", "design"
    }
    
    DATA_FLOW_PATTERNS = {
        "dataflow", "data_flow", "dfd", "flow"
    }
    
    THREAT_PATTERNS = {
        "threat", "threats", "security", "risk"
    }
    
    # Supported file extensions
    TEXT_EXTENSIONS = {".md", ".txt", ".rst", ".json", ".yaml", ".yml"}
    DIAGRAM_EXTENSIONS = {".png", ".jpg", ".jpeg", ".svg", ".pdf", ".mmd", ".puml", ".drawio"}
    
    def __init__(self):
        self.logger = get_logger(__name__)
    
    def scan_directory(self, directory: str) -> ScanResult:
        """
        Scan directory for context files.
        
        Args:
            directory: Path to directory to scan
            
        Returns:
            ScanResult with discovered files and metadata
        """
        dir_path = Path(directory).resolve()
        
        if not dir_path.exists():
            raise FileProcessingError(f"Directory does not exist: {directory}")
        
        if not dir_path.is_dir():
            raise FileProcessingError(f"Path is not a directory: {directory}")
        
        self.logger.info(f"Scanning directory: {dir_path}")
        
        files_found = []
        scan_errors = []
        
        try:
            # Scan all files in directory (non-recursive for now)
            for file_path in dir_path.iterdir():
                if file_path.is_file():
                    try:
                        file_info = self._analyze_file(file_path)
                        if file_info.file_type != FileType.UNKNOWN:
                            files_found.append(file_info)
                            self.logger.debug(f"Found {file_info.file_type.value}: {file_path.name}")
                    except Exception as e:
                        error_msg = f"Error analyzing file {file_path.name}: {e}"
                        scan_errors.append(error_msg)
                        self.logger.warning(error_msg)
        
        except Exception as e:
            raise FileProcessingError(f"Error scanning directory: {e}")
        
        # Determine missing file types
        found_types = {f.file_type for f in files_found}
        all_types = {FileType.README, FileType.ARCHITECTURE_DIAGRAM, 
                    FileType.DATA_FLOW_DIAGRAM, FileType.THREAT_STATEMENTS}
        missing_types = all_types - found_types
        
        result = ScanResult(
            input_directory=dir_path,
            files_found=files_found,
            missing_file_types=missing_types,
            scan_errors=scan_errors
        )
        
        self.logger.info(f"Scan completed: {len(files_found)} files found, "
                        f"{len(missing_types)} types missing")
        
        return result
    
    def _analyze_file(self, file_path: Path) -> FileInfo:
        """
        Analyze a single file to determine its type and properties.
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            FileInfo object with file metadata
        """
        try:
            # Get basic file info
            stat = file_path.stat()
            size = stat.st_size
            
            # Check if file is readable
            is_readable = os.access(file_path, os.R_OK)
            
            # Get MIME type
            mime_type, encoding = mimetypes.guess_type(str(file_path))
            
            # Determine file type based on name and extension
            file_type = self._classify_file(file_path)
            
            return FileInfo(
                path=file_path,
                file_type=file_type,
                size=size,
                is_readable=is_readable,
                mime_type=mime_type,
                encoding=encoding
            )
            
        except Exception as e:
            self.logger.warning(f"Error analyzing file {file_path}: {e}")
            return FileInfo(
                path=file_path,
                file_type=FileType.UNKNOWN,
                size=0,
                is_readable=False
            )
    
    def _classify_file(self, file_path: Path) -> FileType:
        """
        Classify file based on name patterns and extensions.
        
        Args:
            file_path: Path to file to classify
            
        Returns:
            FileType enum value
        """
        filename = file_path.name.lower()
        stem = file_path.stem.lower()
        suffix = file_path.suffix.lower()
        
        # Check for README files
        if filename in self.README_PATTERNS:
            return FileType.README
        
        # Check for threat statement files
        if any(pattern in stem for pattern in self.THREAT_PATTERNS):
            if suffix in self.TEXT_EXTENSIONS:
                return FileType.THREAT_STATEMENTS
        
        # Check for architecture diagrams
        if any(pattern in stem for pattern in self.ARCHITECTURE_PATTERNS):
            if suffix in self.DIAGRAM_EXTENSIONS or suffix in self.TEXT_EXTENSIONS:
                return FileType.ARCHITECTURE_DIAGRAM
        
        # Check for data flow diagrams
        if any(pattern in stem for pattern in self.DATA_FLOW_PATTERNS):
            if suffix in self.DIAGRAM_EXTENSIONS or suffix in self.TEXT_EXTENSIONS:
                return FileType.DATA_FLOW_DIAGRAM
        
        # Special cases for common files
        if filename == "threatcomposer_workspace" and suffix == ".json":
            return FileType.THREAT_STATEMENTS
        
        if "threat" in filename and suffix == ".json":
            return FileType.THREAT_STATEMENTS
        
        return FileType.UNKNOWN
    
    def validate_files(self, scan_result: ScanResult) -> List[str]:
        """
        Validate that discovered files are accessible and contain data.
        
        Args:
            scan_result: Result from directory scan
            
        Returns:
            List of validation error messages
        """
        validation_errors = []
        
        for file_info in scan_result.files_found:
            if not file_info.is_readable:
                validation_errors.append(f"File is not readable: {file_info.path}")
                continue
            
            if file_info.size == 0:
                validation_errors.append(f"File is empty: {file_info.path}")
                continue
            
            # Additional validation for text files
            if file_info.path.suffix.lower() in self.TEXT_EXTENSIONS:
                try:
                    with open(file_info.path, 'r', encoding='utf-8') as f:
                        content = f.read(100)  # Read first 100 chars
                        if not content.strip():
                            validation_errors.append(f"Text file appears to be empty: {file_info.path}")
                except UnicodeDecodeError:
                    validation_errors.append(f"File encoding issue: {file_info.path}")
                except Exception as e:
                    validation_errors.append(f"Error reading file {file_info.path}: {e}")
        
        return validation_errors
    
    def get_missing_files_guidance(self, missing_types: Set[FileType]) -> List[str]:
        """
        Provide guidance on what files are missing and where to find them.
        
        Args:
            missing_types: Set of missing file types
            
        Returns:
            List of guidance messages
        """
        guidance = []
        
        if FileType.README in missing_types:
            guidance.append(
                "README file missing: Please ensure you have a README.md or README.txt file "
                "that describes your application, its architecture, and technologies used."
            )
        
        if FileType.THREAT_STATEMENTS in missing_types:
            guidance.append(
                "Threat statements missing: Please provide a file containing threat statements "
                "(e.g., threats.md, security.md, or ThreatComposer JSON export). "
                "Each threat should include severity information (high/medium/low)."
            )
        
        if FileType.ARCHITECTURE_DIAGRAM in missing_types:
            guidance.append(
                "Architecture diagram missing (optional): Consider adding an architecture diagram "
                "(architecture.png, system_design.md, etc.) to provide visual context."
            )
        
        if FileType.DATA_FLOW_DIAGRAM in missing_types:
            guidance.append(
                "Data flow diagram missing (optional): Consider adding a data flow diagram "
                "(dataflow.mmd, dfd.png, etc.) to show how data moves through your system."
            )
        
        return guidance