"""Centralized logging utility for ThreatForest"""

import logging
import json
import uuid
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from contextvars import ContextVar

# Correlation ID context variable for request tracing
correlation_id_var: ContextVar[str] = ContextVar('correlation_id', default=None)


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'correlation_id': correlation_id_var.get()
        }
        
        # Add extra fields if present
        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)


class ThreatForestLogger:
    """Centralized logger for ThreatForest tools with structured logging"""
    
    _instance: Optional['ThreatForestLogger'] = None
    _logger: Optional[logging.Logger] = None
    _log_file_path: Optional[Path] = None
    _json_mode: bool = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    def initialize(cls, output_dir: Path = None, json_mode: bool = False) -> Path:
        """Initialize the logger with output directory
        
        Args:
            output_dir: Directory for log files (default: ./output)
            json_mode: Use JSON format for logs (default: False)
            
        Returns:
            Path to the log file
        """
        # If already initialized, return existing log file path
        if cls._log_file_path is not None and cls._log_file_path.exists():
            return cls._log_file_path
            
        if output_dir is None:
            output_dir = Path.cwd() / "output"
        
        # Ensure logs go into logs/ subdirectory
        log_dir = output_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create log file with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        cls._log_file_path = log_dir / f"threatforest_run_{timestamp}.log"
        cls._json_mode = json_mode
        
        # Configure root logger
        cls._logger = logging.getLogger('ThreatForest')
        cls._logger.setLevel(logging.DEBUG)
        cls._logger.handlers.clear()  # Clear any existing handlers
        
        # File handler with append mode for multi-process logging
        file_handler = logging.FileHandler(cls._log_file_path, mode='a', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        
        if json_mode:
            formatter = StructuredFormatter()
        else:
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


# Helper functions for structured logging

def set_correlation_id(correlation_id: str = None):
    """Set correlation ID for request tracing"""
    if correlation_id is None:
        correlation_id = str(uuid.uuid4())
    correlation_id_var.set(correlation_id)
    return correlation_id


def get_correlation_id() -> Optional[str]:
    """Get current correlation ID"""
    return correlation_id_var.get()


def log_with_context(logger: logging.Logger, level: str, message: str, **kwargs):
    """Log message with additional context fields"""
    record = logger.makeRecord(
        logger.name,
        getattr(logging, level.upper()),
        "(unknown file)", 0,
        message, (), None
    )
    record.extra_fields = kwargs
    logger.handle(record)


def log_performance(logger: logging.Logger, operation: str, duration: float, **kwargs):
    """Log performance metrics"""
    log_with_context(
        logger, 'INFO',
        f"Performance: {operation}",
        operation=operation,
        duration_seconds=duration,
        **kwargs
    )

