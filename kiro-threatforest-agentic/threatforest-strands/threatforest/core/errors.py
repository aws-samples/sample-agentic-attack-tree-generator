"""Error types and exception classes for ThreatForest"""
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Dict, Any


class ErrorSeverity(str, Enum):
    """Error severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ThreatForestError:
    """Standard error data structure"""
    code: str
    message: str
    severity: ErrorSeverity
    context: Dict[str, Any]
    recoverable: bool
    recovery_suggestion: Optional[str] = None


class BedrockError(Exception):
    """Errors related to AWS Bedrock API calls"""
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        self.message = message
        self.context = context or {}
        super().__init__(self.message)


class ValidationError(Exception):
    """Errors related to input validation"""
    def __init__(self, message: str, field: Optional[str] = None, context: Optional[Dict[str, Any]] = None):
        self.message = message
        self.field = field
        self.context = context or {}
        super().__init__(self.message)


class FileOperationError(Exception):
    """Errors related to file operations"""
    def __init__(self, message: str, file_path: Optional[str] = None, context: Optional[Dict[str, Any]] = None):
        self.message = message
        self.file_path = file_path
        self.context = context or {}
        super().__init__(self.message)


class StateError(Exception):
    """Errors related to state management"""
    def __init__(self, message: str, state: Optional[str] = None, context: Optional[Dict[str, Any]] = None):
        self.message = message
        self.state = state
        self.context = context or {}
        super().__init__(self.message)


class ConfigurationError(Exception):
    """Errors related to configuration"""
    def __init__(self, message: str, config_key: Optional[str] = None, context: Optional[Dict[str, Any]] = None):
        self.message = message
        self.config_key = config_key
        self.context = context or {}
        super().__init__(self.message)
