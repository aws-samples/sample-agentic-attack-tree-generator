"""
Error handling and logging utilities for ThreatForest.

This module provides comprehensive error handling with categorized responses,
graceful degradation, and detailed logging capabilities.
"""

import logging
import sys
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError


class ErrorCategory(Enum):
    """Categories of errors that can occur in ThreatForest."""
    AUTHENTICATION = "authentication"
    FILE_SYSTEM = "file_system"
    AGENT_PROCESSING = "agent_processing"
    WORKFLOW = "workflow"
    CONFIGURATION = "configuration"
    VALIDATION = "validation"
    NETWORK = "network"
    UNKNOWN = "unknown"


class ErrorSeverity(Enum):
    """Severity levels for errors."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ErrorContext:
    """Context information for an error."""
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    recoverable: bool = True
    suggested_actions: List[str] = field(default_factory=list)
    error_code: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error context to dictionary."""
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
            "recoverable": self.recoverable,
            "suggested_actions": self.suggested_actions,
            "error_code": self.error_code
        }


class ErrorHandler:
    """
    Comprehensive error handler for ThreatForest with categorized responses
    and recovery strategies.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the error handler."""
        self.logger = logger or logging.getLogger(__name__)
        self.error_history: List[ErrorContext] = []
        self.retry_counts: Dict[str, int] = {}
        self.max_retries = 3
        self.base_retry_delay = 1.0
        
    def handle_error(self, 
                    error: Exception, 
                    category: ErrorCategory = ErrorCategory.UNKNOWN,
                    context: Optional[Dict[str, Any]] = None,
                    operation: Optional[str] = None) -> ErrorContext:
        """
        Handle an error with appropriate categorization and response.
        
        Args:
            error: The exception that occurred
            category: Category of the error
            context: Additional context information
            operation: The operation that was being performed
            
        Returns:
            ErrorContext with details about the error and suggested actions
        """
        context = context or {}
        
        # Determine error category if not provided
        if category == ErrorCategory.UNKNOWN:
            category = self._categorize_error(error)
            
        # Create error context
        error_context = self._create_error_context(error, category, context, operation)
        
        # Log the error
        self._log_error(error_context, error)
        
        # Store in history
        self.error_history.append(error_context)
        
        # Apply recovery strategy
        self._apply_recovery_strategy(error_context)
        
        return error_context
    
    def handle_api_error(self, error: Exception, operation: str = "API call") -> ErrorContext:
        """Handle Bedrock API and AWS-related errors."""
        context = {"operation": operation}
        
        if isinstance(error, NoCredentialsError):
            return self._handle_credentials_error(error, context)
        elif isinstance(error, ClientError):
            return self._handle_client_error(error, context)
        elif isinstance(error, BotoCoreError):
            return self._handle_botocore_error(error, context)
        else:
            return self.handle_error(error, ErrorCategory.AUTHENTICATION, context, operation)
    
    def handle_file_error(self, error: Exception, file_path: Optional[str] = None) -> ErrorContext:
        """Handle file system related errors."""
        context = {"file_path": file_path} if file_path else {}
        
        if isinstance(error, FileNotFoundError):
            error_context = self._handle_file_not_found(error, context)
        elif isinstance(error, PermissionError):
            error_context = self._handle_permission_error(error, context)
        elif isinstance(error, OSError):
            error_context = self._handle_os_error(error, context)
        else:
            return self.handle_error(error, ErrorCategory.FILE_SYSTEM, context, "file operation")
        
        # Log and store the error context
        self._log_error(error_context, error)
        self.error_history.append(error_context)
        self._apply_recovery_strategy(error_context)
        
        return error_context
    
    def handle_agent_error(self, error: Exception, agent_name: str, phase: str = "") -> ErrorContext:
        """Handle agent processing errors."""
        context = {
            "agent_name": agent_name,
            "phase": phase,
            "retry_count": self.retry_counts.get(f"{agent_name}_{phase}", 0)
        }
        
        error_context = self.handle_error(error, ErrorCategory.AGENT_PROCESSING, context, 
                                        f"{agent_name} processing")
        
        # Increment retry count
        retry_key = f"{agent_name}_{phase}"
        self.retry_counts[retry_key] = self.retry_counts.get(retry_key, 0) + 1
        
        return error_context
    
    def handle_workflow_error(self, error: Exception, workflow_phase: str) -> ErrorContext:
        """Handle workflow orchestration errors."""
        context = {"workflow_phase": workflow_phase}
        return self.handle_error(error, ErrorCategory.WORKFLOW, context, "workflow execution")
    
    def should_retry(self, error_context: ErrorContext, operation_key: str) -> bool:
        """
        Determine if an operation should be retried based on error context.
        
        Args:
            error_context: The error context
            operation_key: Unique key for the operation
            
        Returns:
            True if the operation should be retried
        """
        if not error_context.recoverable:
            return False
            
        retry_count = self.retry_counts.get(operation_key, 0)
        
        # Don't retry critical errors
        if error_context.severity == ErrorSeverity.CRITICAL:
            return False
            
        # Check retry limits
        if retry_count >= self.max_retries:
            self.logger.warning(f"Max retries ({self.max_retries}) exceeded for {operation_key}")
            return False
            
        return True
    
    def calculate_retry_delay(self, retry_count: int) -> float:
        """Calculate exponential backoff delay."""
        return self.base_retry_delay * (2 ** retry_count)
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get a summary of all errors encountered."""
        if not self.error_history:
            return {"total_errors": 0, "by_category": {}, "by_severity": {}}
            
        by_category = {}
        by_severity = {}
        
        for error_ctx in self.error_history:
            # Count by category
            cat = error_ctx.category.value
            by_category[cat] = by_category.get(cat, 0) + 1
            
            # Count by severity
            sev = error_ctx.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        return {
            "total_errors": len(self.error_history),
            "by_category": by_category,
            "by_severity": by_severity,
            "recent_errors": [ctx.to_dict() for ctx in self.error_history[-5:]]
        }
    
    def clear_error_history(self):
        """Clear the error history."""
        self.error_history.clear()
        self.retry_counts.clear()
    
    def _categorize_error(self, error: Exception) -> ErrorCategory:
        """Automatically categorize an error based on its type."""
        if isinstance(error, (NoCredentialsError, ClientError, BotoCoreError)):
            return ErrorCategory.AUTHENTICATION
        elif isinstance(error, (FileNotFoundError, PermissionError, OSError)):
            return ErrorCategory.FILE_SYSTEM
        elif isinstance(error, (ValueError, TypeError, KeyError)):
            return ErrorCategory.VALIDATION
        elif isinstance(error, (ConnectionError, TimeoutError)):
            return ErrorCategory.NETWORK
        else:
            return ErrorCategory.UNKNOWN
    
    def _create_error_context(self, 
                            error: Exception, 
                            category: ErrorCategory,
                            context: Dict[str, Any],
                            operation: Optional[str]) -> ErrorContext:
        """Create an ErrorContext from an exception."""
        severity = self._determine_severity(error, category)
        message = str(error)
        
        # Add operation to context
        if operation:
            context["operation"] = operation
            
        # Determine if error is recoverable
        recoverable = self._is_recoverable(error, category)
        
        # Generate suggested actions
        suggested_actions = self._generate_suggested_actions(error, category, context)
        
        # Generate error code
        error_code = self._generate_error_code(error, category)
        
        return ErrorContext(
            category=category,
            severity=severity,
            message=message,
            details=context,
            recoverable=recoverable,
            suggested_actions=suggested_actions,
            error_code=error_code
        )
    
    def _determine_severity(self, error: Exception, category: ErrorCategory) -> ErrorSeverity:
        """Determine the severity of an error."""
        if isinstance(error, (NoCredentialsError, PermissionError)):
            return ErrorSeverity.CRITICAL
        elif isinstance(error, (ClientError, FileNotFoundError)):
            return ErrorSeverity.HIGH
        elif isinstance(error, (ValueError, TypeError)):
            return ErrorSeverity.MEDIUM
        else:
            return ErrorSeverity.LOW
    
    def _is_recoverable(self, error: Exception, category: ErrorCategory) -> bool:
        """Determine if an error is recoverable."""
        # Critical authentication errors are not recoverable
        if isinstance(error, NoCredentialsError):
            return False
            
        # Permission errors are not recoverable
        if isinstance(error, PermissionError):
            return False
            
        # Most other errors are recoverable with retry or alternative approaches
        return True
    
    def _generate_suggested_actions(self, 
                                  error: Exception, 
                                  category: ErrorCategory,
                                  context: Dict[str, Any]) -> List[str]:
        """Generate suggested actions for error recovery."""
        actions = []
        
        if category == ErrorCategory.AUTHENTICATION:
            if isinstance(error, NoCredentialsError):
                actions.extend([
                    "Configure AWS credentials using 'aws configure'",
                    "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables",
                    "Ensure AWS profile is properly configured"
                ])
            elif isinstance(error, ClientError):
                actions.extend([
                    "Check AWS region configuration",
                    "Verify Bedrock service availability in your region",
                    "Check API quotas and limits"
                ])
                
        elif category == ErrorCategory.FILE_SYSTEM:
            if isinstance(error, FileNotFoundError):
                actions.extend([
                    "Verify the file path is correct",
                    "Check if required context files exist",
                    "Run from the correct directory"
                ])
            elif isinstance(error, PermissionError):
                actions.extend([
                    "Check file permissions",
                    "Run with appropriate user privileges",
                    "Verify directory write permissions"
                ])
                
        elif category == ErrorCategory.AGENT_PROCESSING:
            actions.extend([
                "Retry the operation",
                "Check input data format",
                "Verify AI model availability"
            ])
            
        elif category == ErrorCategory.WORKFLOW:
            actions.extend([
                "Check workflow configuration",
                "Verify all required agents are initialized",
                "Review partial results if available"
            ])
        
        return actions
    
    def _generate_error_code(self, error: Exception, category: ErrorCategory) -> str:
        """Generate a unique error code."""
        category_code = category.value.upper()[:3]
        error_type = type(error).__name__[:3].upper()
        timestamp = int(time.time()) % 10000
        return f"TF-{category_code}-{error_type}-{timestamp}"
    
    def _log_error(self, error_context: ErrorContext, original_error: Exception):
        """Log an error with appropriate level."""
        log_level = {
            ErrorSeverity.CRITICAL: logging.CRITICAL,
            ErrorSeverity.HIGH: logging.ERROR,
            ErrorSeverity.MEDIUM: logging.WARNING,
            ErrorSeverity.LOW: logging.INFO,
            ErrorSeverity.INFO: logging.INFO
        }.get(error_context.severity, logging.ERROR)
        
        self.logger.log(
            log_level,
            f"[{error_context.error_code}] {error_context.category.value.title()} Error: {error_context.message}",
            extra={
                "error_context": error_context.to_dict(),
                "exception": original_error
            }
        )
    
    def _apply_recovery_strategy(self, error_context: ErrorContext):
        """Apply recovery strategies based on error context."""
        if error_context.category == ErrorCategory.AGENT_PROCESSING:
            self.logger.info(f"Applying recovery strategy for agent processing error: {error_context.error_code}")
            # Recovery strategies are handled by the orchestrator
            
        elif error_context.category == ErrorCategory.FILE_SYSTEM:
            if "file_path" in error_context.details:
                self.logger.info(f"File system error for: {error_context.details['file_path']}")
    
    def _handle_credentials_error(self, error: NoCredentialsError, context: Dict[str, Any]) -> ErrorContext:
        """Handle AWS credentials errors."""
        return ErrorContext(
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.CRITICAL,
            message="AWS credentials not found or invalid",
            details=context,
            recoverable=False,
            suggested_actions=[
                "Configure AWS credentials using 'aws configure'",
                "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables",
                "Ensure AWS profile is properly configured",
                "Check ~/.aws/credentials file"
            ],
            error_code=self._generate_error_code(error, ErrorCategory.AUTHENTICATION)
        )
    
    def _handle_client_error(self, error: ClientError, context: Dict[str, Any]) -> ErrorContext:
        """Handle AWS ClientError exceptions."""
        error_code = error.response.get('Error', {}).get('Code', 'Unknown')
        error_message = error.response.get('Error', {}).get('Message', str(error))
        
        context.update({
            "aws_error_code": error_code,
            "aws_error_message": error_message,
            "http_status_code": error.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
        })
        
        severity = ErrorSeverity.HIGH
        recoverable = True
        actions = ["Check AWS service status", "Verify API permissions"]
        
        if error_code in ['ThrottlingException', 'TooManyRequestsException']:
            severity = ErrorSeverity.MEDIUM
            actions.extend(["Reduce request rate", "Implement exponential backoff"])
        elif error_code in ['AccessDeniedException', 'UnauthorizedOperation']:
            severity = ErrorSeverity.CRITICAL
            recoverable = False
            actions.extend(["Check IAM permissions", "Verify service access policies"])
        
        return ErrorContext(
            category=ErrorCategory.AUTHENTICATION,
            severity=severity,
            message=f"AWS API Error: {error_message}",
            details=context,
            recoverable=recoverable,
            suggested_actions=actions,
            error_code=self._generate_error_code(error, ErrorCategory.AUTHENTICATION)
        )
    
    def _handle_botocore_error(self, error: BotoCoreError, context: Dict[str, Any]) -> ErrorContext:
        """Handle BotoCoreError exceptions."""
        return ErrorContext(
            category=ErrorCategory.NETWORK,
            severity=ErrorSeverity.MEDIUM,
            message=f"AWS SDK Error: {str(error)}",
            details=context,
            recoverable=True,
            suggested_actions=[
                "Check internet connection",
                "Verify AWS service endpoints",
                "Retry the operation"
            ],
            error_code=self._generate_error_code(error, ErrorCategory.NETWORK)
        )
    
    def _handle_file_not_found(self, error: FileNotFoundError, context: Dict[str, Any]) -> ErrorContext:
        """Handle file not found errors."""
        file_path = context.get("file_path", "unknown")
        
        return ErrorContext(
            category=ErrorCategory.FILE_SYSTEM,
            severity=ErrorSeverity.HIGH,
            message=f"Required file not found: {file_path}",
            details=context,
            recoverable=True,
            suggested_actions=[
                f"Create the missing file: {file_path}",
                "Check if you're running from the correct directory",
                "Verify file path spelling and case sensitivity",
                "Check if file was moved or deleted"
            ],
            error_code=self._generate_error_code(error, ErrorCategory.FILE_SYSTEM)
        )
    
    def _handle_permission_error(self, error: PermissionError, context: Dict[str, Any]) -> ErrorContext:
        """Handle permission errors."""
        file_path = context.get("file_path", "unknown")
        
        return ErrorContext(
            category=ErrorCategory.FILE_SYSTEM,
            severity=ErrorSeverity.CRITICAL,
            message=f"Permission denied accessing: {file_path}",
            details=context,
            recoverable=False,
            suggested_actions=[
                f"Check file permissions for: {file_path}",
                "Run with appropriate user privileges",
                "Verify directory permissions",
                "Check file ownership"
            ],
            error_code=self._generate_error_code(error, ErrorCategory.FILE_SYSTEM)
        )
    
    def _handle_os_error(self, error: OSError, context: Dict[str, Any]) -> ErrorContext:
        """Handle general OS errors."""
        return ErrorContext(
            category=ErrorCategory.FILE_SYSTEM,
            severity=ErrorSeverity.MEDIUM,
            message=f"Operating system error: {str(error)}",
            details=context,
            recoverable=True,
            suggested_actions=[
                "Check system resources (disk space, memory)",
                "Verify file system integrity",
                "Retry the operation",
                "Check system logs for more details"
            ],
            error_code=self._generate_error_code(error, ErrorCategory.FILE_SYSTEM)
        )


def setup_logging(log_level: str = "INFO", 
                 log_file: Optional[str] = None,
                 include_console: bool = True) -> logging.Logger:
    """
    Set up comprehensive logging for ThreatForest.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        include_console: Whether to include console logging
        
    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger("threatforest")
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    if include_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, log_level.upper()))
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        # Ensure log directory exists
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)  # File gets all messages
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for a specific module."""
    return logging.getLogger(f"threatforest.{name}")