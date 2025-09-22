"""
Utility functions and logging configuration for ThreatForest.
"""

import logging
import os
from pathlib import Path
from typing import Optional


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> None:
    """
    Set up logging configuration for ThreatForest.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
    """
    # Create logs directory if it doesn't exist
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Configure logging format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Set up handlers
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for the given name."""
    return logging.getLogger(name)


def ensure_output_directory(output_dir: str) -> Path:
    """
    Ensure output directory exists and return Path object.
    
    Args:
        output_dir: Path to output directory
        
    Returns:
        Path object for the output directory
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Create subdirectories
    (output_path / "attack_trees").mkdir(exist_ok=True)
    (output_path / "logs").mkdir(exist_ok=True)
    
    return output_path


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a string to be safe for use as a filename.
    
    Args:
        filename: Original filename string
        
    Returns:
        Sanitized filename string
    """
    # Replace spaces and special characters with hyphens
    import re
    sanitized = re.sub(r'[^\w\-_.]', '-', filename)
    # Remove multiple consecutive hyphens
    sanitized = re.sub(r'-+', '-', sanitized)
    # Remove leading/trailing hyphens
    sanitized = sanitized.strip('-')
    return sanitized.lower()