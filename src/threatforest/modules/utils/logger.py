"""Centralized logging utility for ThreatForest"""

import logging
import json
import uuid
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from contextvars import ContextVar
from threatforest.config import ROOT_DIR

# Correlation ID context variable for request tracing
correlation_id_var: ContextVar[str] = ContextVar('correlation_id', default=None)


class SuppressStrandsWarningsFilter(logging.Filter):
    """Filter to suppress WARNING level logs from Strands framework
    
    This filter allows:
    - All ThreatForest logs (regardless of level)
    - ERROR and CRITICAL from Strands (go to file only)
    - Blocks WARNING and below from Strands going to console
    """
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter log records
        
        Args:
            record: Log record to filter
            
        Returns:
            True if record should be logged, False otherwise
        """
        # Always allow ThreatForest logs
        if record.name.startswith('ThreatForest'):
            return True
        
        # For Strands logs, only allow ERROR and above
        if record.name.startswith('strands'):
            return record.levelno >= logging.ERROR
        
        # Allow everything else
        return True


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
            output_dir: Directory for log files (default: .threatforest/logs/)
            json_mode: Use JSON format for logs (default: False)
            
        Returns:
            Path to the log file
        """
        # If already initialized, return existing log file path
        if cls._log_file_path is not None and cls._log_file_path.exists():
            return cls._log_file_path
        
        # Use ROOT_DIR/.threatforest/logs/ for log storage
        base_log_dir = ROOT_DIR / ".threatforest" / "logs"
        
        # Cleanup old logs before creating new ones (30-day TTL)
        cls._cleanup_old_logs(base_log_dir, retention_days=30)
        
        # Create timestamp subdirectory for this run
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_dir = base_log_dir / timestamp
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Simplified filename (no timestamp in filename, directory has it)
        cls._log_file_path = log_dir / "threatforest.log"
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
        
        # Configure Strands framework logging based on config
        cls._configure_strands_logging(log_dir)
        
        return cls._log_file_path
    
    @classmethod
    def _cleanup_old_logs(cls, base_log_dir: Path, retention_days: int = 30):
        """Remove log directories older than retention_days
        
        Args:
            base_log_dir: Base directory containing timestamped log directories
            retention_days: Number of days to retain logs (default: 30)
        """
        if not base_log_dir.exists():
            return
        
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        for log_dir in base_log_dir.iterdir():
            if log_dir.is_dir():
                try:
                    # Parse timestamp from directory name (YYYYMMDD_HHMMSS)
                    dir_timestamp = datetime.strptime(log_dir.name, "%Y%m%d_%H%M%S")
                    if dir_timestamp < cutoff_date:
                        shutil.rmtree(log_dir)
                        # Note: Can't log this yet as logger may not be initialized
                except (ValueError, OSError):
                    # Skip directories that don't match expected format or can't be deleted
                    pass
    
    @classmethod
    def _configure_strands_logging(cls, log_dir: Path):
        """Configure Strands framework logging to suppress console warnings
        
        Always suppresses intermediate Strands warnings/errors from CLI while
        capturing everything in a dedicated log file.
        
        Args:
            log_dir: Directory for log files (timestamp subdirectory)
        """
        # Get the root Strands logger
        strands_logger = logging.getLogger('strands')
        strands_logger.setLevel(logging.DEBUG)
        
        # Remove any existing console handlers from Strands logger
        for handler in strands_logger.handlers[:]:
            if isinstance(handler, logging.StreamHandler) and handler.stream.name in ['<stdout>', '<stderr>']:
                strands_logger.removeHandler(handler)
        
        # Add file handler for Strands logs in same timestamp directory
        strands_file_handler = logging.FileHandler(
            log_dir / "strands.log",
            mode='a',
            encoding='utf-8'
        )
        strands_file_handler.setLevel(logging.DEBUG)
        strands_file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        strands_logger.addHandler(strands_file_handler)
        
        # Add filter to root logger to suppress Strands warnings from any console output
        root_logger = logging.getLogger()
        suppress_filter = SuppressStrandsWarningsFilter()
        
        # Apply filter to all console-bound handlers on root logger
        for handler in root_logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.addFilter(suppress_filter)
        
        # Prevent propagation to root logger to avoid duplicate console output
        strands_logger.propagate = False
        
        cls._logger.debug("Configured Strands logging: intermediate errors suppressed from CLI, all logs in file")
    
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
