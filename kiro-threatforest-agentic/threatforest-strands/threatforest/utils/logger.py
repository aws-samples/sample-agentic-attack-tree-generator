"""Centralized logging utility for ThreatForest"""

import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

class ThreatForestLogger:
    """Centralized logger for ThreatForest tools"""
    
    _instance: Optional['ThreatForestLogger'] = None
    _logger: Optional[logging.Logger] = None
    _log_file_path: Optional[Path] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    def initialize(cls, output_dir: Path = None) -> Path:
        """Initialize the logger with output directory
        
        Args:
            output_dir: Directory for log files (default: ./threatforest_output)
            
        Returns:
            Path to the log file
        """
        if output_dir is None:
            output_dir = Path.cwd() / "threatforest_output"
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create log file with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        cls._log_file_path = output_dir / f"threatforest_run_{timestamp}.log"
        
        # Configure root logger
        cls._logger = logging.getLogger('ThreatForest')
        cls._logger.setLevel(logging.DEBUG)
        cls._logger.handlers.clear()  # Clear any existing handlers
        
        # File handler with verbose formatting
        file_handler = logging.FileHandler(cls._log_file_path, mode='w', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        cls._logger.addHandler(file_handler)
        
        cls._logger.info("="*80)
        cls._logger.info("ThreatForest Session Started")
        cls._logger.info("="*80)
        cls._logger.info(f"Log file: {cls._log_file_path}")
        
        return cls._log_file_path
    
    @classmethod
    def get_logger(cls, name: str = None) -> logging.Logger:
        """Get a logger instance
        
        Args:
            name: Optional name for the logger (will be appended to 'ThreatForest')
            
        Returns:
            Logger instance
        """
        if cls._logger is None:
            cls.initialize()
        
        if name:
            return logging.getLogger(f'ThreatForest.{name}')
        return cls._logger
    
    @classmethod
    def get_log_file_path(cls) -> Optional[Path]:
        """Get the current log file path"""
        return cls._log_file_path
    
    @classmethod
    def close(cls):
        """Close all handlers and finalize logging"""
        if cls._logger:
            cls._logger.info("="*80)
            cls._logger.info("ThreatForest Session Completed")
            cls._logger.info("="*80)
            
            for handler in cls._logger.handlers[:]:
                handler.close()
                cls._logger.removeHandler(handler)
