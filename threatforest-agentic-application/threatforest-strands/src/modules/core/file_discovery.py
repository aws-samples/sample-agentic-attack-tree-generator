"""File discovery for ThreatForest"""
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set


@dataclass
class DiscoveredFiles:
    """Container for discovered files with metadata"""
    threat_models: List[str] = field(default_factory=list)
    source_code: List[str] = field(default_factory=list)
    config_files: List[str] = field(default_factory=list)
    documentation: List[str] = field(default_factory=list)
    diagrams: List[str] = field(default_factory=list)
    all_files: List[str] = field(default_factory=list)
    
    # Metadata
    total_files: int = 0
    total_size_bytes: int = 0
    discovery_time_ms: float = 0
    excluded_dirs: int = 0


class FileDiscovery:
    """Single-pass file discovery with caching"""
    
    # Directories to exclude
    EXCLUDED_DIRS = {
        '.git', '.svn', '.hg', 'node_modules', '__pycache__', '.pytest_cache',
        'venv', 'env', '.venv', 'tf-venv', 'dist', 'build', '.egg-info',
        'target', 'bin', 'obj', '.idea', '.vscode', '.DS_Store'
    }
    
    # File extensions by category
    THREAT_EXTENSIONS = {'.md', '.json', '.yaml', '.yml', '.tc'}
    SOURCE_EXTENSIONS = {'.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.c', '.cpp', '.h', '.cs'}
    CONFIG_EXTENSIONS = {'.json', '.yaml', '.yml', '.toml', '.ini', '.conf', '.config', '.xml'}
    DOC_EXTENSIONS = {'.md', '.txt', '.rst', '.adoc'}
    DIAGRAM_EXTENSIONS = {'.mmd', '.puml', '.drawio', '.png', '.jpg', '.svg'}
    
    # Threat-related keywords
    THREAT_KEYWORDS = {'threat', 'security', 'risk', 'attack', 'vulnerability'}
    
    # Max file size (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024
    
    @staticmethod
    def discover(project_path: str) -> DiscoveredFiles:
        """Discover files in project with single-pass walk
        
        Args:
            project_path: Root directory to scan
            
        Returns:
            DiscoveredFiles with categorized file lists
        """
        start_time = time.time()
        result = DiscoveredFiles()
        path = Path(project_path)
        
        if not path.exists():
            return result
        
        for root, dirs, files in os.walk(project_path):
            # Filter out excluded directories in-place
            dirs[:] = [d for d in dirs if d not in FileDiscovery.EXCLUDED_DIRS]
            result.excluded_dirs += len([d for d in os.listdir(root) 
                                        if d in FileDiscovery.EXCLUDED_DIRS])
            
            for file in files:
                file_path = os.path.join(root, file)
                
                try:
                    # Check file size
                    file_size = os.path.getsize(file_path)
                    if file_size > FileDiscovery.MAX_FILE_SIZE:
                        continue
                    
                    result.total_size_bytes += file_size
                    result.all_files.append(file_path)
                    
                    file_lower = file.lower()
                    ext = Path(file).suffix.lower()
                    
                    # Categorize file (single pass, multiple categories possible)
                    # Threat models (highest priority)
                    if ('threat' in file_lower or 
                        any(kw in file_lower for kw in FileDiscovery.THREAT_KEYWORDS) or
                        ext == '.tc'):
                        result.threat_models.append(file_path)
                    
                    # Source code
                    if ext in FileDiscovery.SOURCE_EXTENSIONS:
                        result.source_code.append(file_path)
                    
                    # Config files
                    if (ext in FileDiscovery.CONFIG_EXTENSIONS and 
                        any(name in file_lower for name in ['config', 'settings', 'package', 'requirements'])):
                        result.config_files.append(file_path)
                    
                    # Documentation
                    if ext in FileDiscovery.DOC_EXTENSIONS and 'threat' not in file_lower:
                        result.documentation.append(file_path)
                    
                    # Diagrams
                    if ext in FileDiscovery.DIAGRAM_EXTENSIONS:
                        result.diagrams.append(file_path)
                        
                except (OSError, PermissionError):
                    continue
        
        result.total_files = len(result.all_files)
        result.discovery_time_ms = (time.time() - start_time) * 1000
        
        return result
    
    @staticmethod
    def clear_cache():
        """Clear the discovery cache"""
        FileDiscovery.discover.cache_clear()
