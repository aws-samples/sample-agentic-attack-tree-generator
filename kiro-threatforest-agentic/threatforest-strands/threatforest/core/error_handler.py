"""Centralized error handling for ThreatForest"""
from typing import Dict, Any, Optional
from .errors import (
    ThreatForestError, ErrorSeverity, BedrockError, ValidationError,
    FileOperationError, StateError, ConfigurationError
)


class ErrorHandler:
    """Centralized error handler with recovery strategies"""
    
    @staticmethod
    def handle_bedrock_error(error: Exception, context: Optional[Dict[str, Any]] = None) -> ThreatForestError:
        """Handle AWS Bedrock API errors"""
        error_msg = str(error)
        ctx = context or {}
        
        # Check for throttling
        if "ThrottlingException" in error_msg or "TooManyRequestsException" in error_msg:
            return ThreatForestError(
                code="BEDROCK_THROTTLED",
                message="AWS Bedrock API rate limit exceeded",
                severity=ErrorSeverity.HIGH,
                context=ctx,
                recoverable=True,
                recovery_suggestion="Retry with exponential backoff. Consider reducing request rate."
            )
        
        # Check for authentication
        if "UnauthorizedException" in error_msg or "AccessDeniedException" in error_msg:
            return ThreatForestError(
                code="BEDROCK_AUTH_FAILED",
                message="AWS Bedrock authentication failed",
                severity=ErrorSeverity.CRITICAL,
                context=ctx,
                recoverable=False,
                recovery_suggestion="Check AWS credentials and IAM permissions for Bedrock access."
            )
        
        # Generic Bedrock error
        return ThreatForestError(
            code="BEDROCK_ERROR",
            message=f"AWS Bedrock API error: {error_msg}",
            severity=ErrorSeverity.HIGH,
            context=ctx,
            recoverable=True,
            recovery_suggestion="Check AWS service status and retry."
        )
    
    @staticmethod
    def handle_validation_error(error: ValidationError, context: Optional[Dict[str, Any]] = None) -> ThreatForestError:
        """Handle validation errors"""
        ctx = context or {}
        if error.field:
            ctx["field"] = error.field
        
        return ThreatForestError(
            code="VALIDATION_ERROR",
            message=error.message,
            severity=ErrorSeverity.MEDIUM,
            context=ctx,
            recoverable=True,
            recovery_suggestion="Check input parameters and correct invalid values."
        )
    
    @staticmethod
    def handle_file_error(error: FileOperationError, context: Optional[Dict[str, Any]] = None) -> ThreatForestError:
        """Handle file operation errors"""
        ctx = context or {}
        if error.file_path:
            ctx["file_path"] = error.file_path
        
        return ThreatForestError(
            code="FILE_ERROR",
            message=error.message,
            severity=ErrorSeverity.MEDIUM,
            context=ctx,
            recoverable=True,
            recovery_suggestion="Check file path and permissions."
        )
    
    @staticmethod
    def handle_state_error(error: StateError, context: Optional[Dict[str, Any]] = None) -> ThreatForestError:
        """Handle state management errors"""
        ctx = context or {}
        if error.state:
            ctx["state"] = error.state
        
        return ThreatForestError(
            code="STATE_ERROR",
            message=error.message,
            severity=ErrorSeverity.HIGH,
            context=ctx,
            recoverable=True,
            recovery_suggestion="Clear state and restart workflow."
        )
    
    @staticmethod
    def handle_generic_error(error: Exception, context: Optional[Dict[str, Any]] = None) -> ThreatForestError:
        """Handle generic errors"""
        return ThreatForestError(
            code="UNKNOWN_ERROR",
            message=str(error),
            severity=ErrorSeverity.HIGH,
            context=context or {},
            recoverable=False,
            recovery_suggestion="Contact support with error details."
        )
    
    @staticmethod
    def to_dict(error: ThreatForestError) -> Dict[str, Any]:
        """Convert error to dictionary for serialization"""
        return {
            "error": {
                "code": error.code,
                "message": error.message,
                "severity": error.severity.value,
                "context": error.context,
                "recoverable": error.recoverable,
                "recovery_suggestion": error.recovery_suggestion
            }
        }
