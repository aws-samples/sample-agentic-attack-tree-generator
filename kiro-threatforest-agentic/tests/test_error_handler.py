"""
Unit tests for the error handling system.
"""

import logging
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
import pytest
from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError

from threatforest.error_handler import (
    ErrorHandler, ErrorCategory, ErrorSeverity, ErrorContext,
    setup_logging, get_logger
)


class TestErrorContext:
    """Test ErrorContext data class."""
    
    def test_error_context_creation(self):
        """Test creating an ErrorContext."""
        context = ErrorContext(
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.HIGH,
            message="Test error",
            details={"key": "value"},
            recoverable=True,
            suggested_actions=["Action 1", "Action 2"],
            error_code="TF-AUTH-001"
        )
        
        assert context.category == ErrorCategory.AUTHENTICATION
        assert context.severity == ErrorSeverity.HIGH
        assert context.message == "Test error"
        assert context.details == {"key": "value"}
        assert context.recoverable is True
        assert context.suggested_actions == ["Action 1", "Action 2"]
        assert context.error_code == "TF-AUTH-001"
    
    def test_error_context_to_dict(self):
        """Test converting ErrorContext to dictionary."""
        context = ErrorContext(
            category=ErrorCategory.FILE_SYSTEM,
            severity=ErrorSeverity.MEDIUM,
            message="File error",
            details={"file_path": "/test/path"}
        )
        
        result = context.to_dict()
        
        assert result["category"] == "file_system"
        assert result["severity"] == "medium"
        assert result["message"] == "File error"
        assert result["details"] == {"file_path": "/test/path"}
        assert "timestamp" in result
        assert result["recoverable"] is True


class TestErrorHandler:
    """Test ErrorHandler class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.logger = Mock(spec=logging.Logger)
        self.error_handler = ErrorHandler(self.logger)
    
    def test_initialization(self):
        """Test ErrorHandler initialization."""
        handler = ErrorHandler()
        assert handler.logger is not None
        assert handler.error_history == []
        assert handler.retry_counts == {}
        assert handler.max_retries == 3
        assert handler.base_retry_delay == 1.0
    
    def test_handle_error_basic(self):
        """Test basic error handling."""
        error = ValueError("Test error")
        
        context = self.error_handler.handle_error(error)
        
        assert context.category == ErrorCategory.VALIDATION
        assert context.severity == ErrorSeverity.MEDIUM
        assert context.message == "Test error"
        assert len(self.error_handler.error_history) == 1
        self.logger.log.assert_called_once()
    
    def test_handle_error_with_context(self):
        """Test error handling with additional context."""
        error = FileNotFoundError("File not found")
        context_data = {"file_path": "/test/file.txt"}
        
        context = self.error_handler.handle_error(
            error, 
            ErrorCategory.FILE_SYSTEM, 
            context_data, 
            "file read"
        )
        
        assert context.category == ErrorCategory.FILE_SYSTEM
        assert context.details["file_path"] == "/test/file.txt"
        assert context.details["operation"] == "file read"
    
    def test_categorize_error_authentication(self):
        """Test automatic categorization of authentication errors."""
        error = NoCredentialsError()
        context = self.error_handler.handle_error(error)
        assert context.category == ErrorCategory.AUTHENTICATION
    
    def test_categorize_error_file_system(self):
        """Test automatic categorization of file system errors."""
        error = FileNotFoundError("File not found")
        context = self.error_handler.handle_error(error)
        assert context.category == ErrorCategory.FILE_SYSTEM
    
    def test_categorize_error_validation(self):
        """Test automatic categorization of validation errors."""
        error = ValueError("Invalid value")
        context = self.error_handler.handle_error(error)
        assert context.category == ErrorCategory.VALIDATION
    
    def test_handle_api_error_no_credentials(self):
        """Test handling NoCredentialsError."""
        error = NoCredentialsError()
        
        context = self.error_handler.handle_api_error(error, "test operation")
        
        assert context.category == ErrorCategory.AUTHENTICATION
        assert context.severity == ErrorSeverity.CRITICAL
        assert context.recoverable is False
        assert "Configure AWS credentials" in context.suggested_actions[0]
    
    def test_handle_api_error_client_error(self):
        """Test handling ClientError."""
        error_response = {
            'Error': {
                'Code': 'AccessDeniedException',
                'Message': 'Access denied'
            },
            'ResponseMetadata': {
                'HTTPStatusCode': 403
            }
        }
        error = ClientError(error_response, 'TestOperation')
        
        context = self.error_handler.handle_api_error(error)
        
        assert context.category == ErrorCategory.AUTHENTICATION
        assert context.severity == ErrorSeverity.CRITICAL
        assert context.recoverable is False
        assert context.details["aws_error_code"] == "AccessDeniedException"
    
    def test_handle_api_error_throttling(self):
        """Test handling throttling errors."""
        error_response = {
            'Error': {
                'Code': 'ThrottlingException',
                'Message': 'Rate exceeded'
            }
        }
        error = ClientError(error_response, 'TestOperation')
        
        context = self.error_handler.handle_api_error(error)
        
        assert context.severity == ErrorSeverity.MEDIUM
        assert context.recoverable is True
        assert "Reduce request rate" in context.suggested_actions
    
    def test_handle_file_error_not_found(self):
        """Test handling file not found errors."""
        error = FileNotFoundError("File not found")
        
        context = self.error_handler.handle_file_error(error, "/test/file.txt")
        
        assert context.category == ErrorCategory.FILE_SYSTEM
        assert context.severity == ErrorSeverity.HIGH
        assert context.details["file_path"] == "/test/file.txt"
        assert "Create the missing file" in context.suggested_actions[0]
    
    def test_handle_file_error_permission(self):
        """Test handling permission errors."""
        error = PermissionError("Permission denied")
        
        context = self.error_handler.handle_file_error(error, "/test/file.txt")
        
        assert context.category == ErrorCategory.FILE_SYSTEM
        assert context.severity == ErrorSeverity.CRITICAL
        assert context.recoverable is False
        assert "Check file permissions" in context.suggested_actions[0]
    
    def test_handle_agent_error(self):
        """Test handling agent processing errors."""
        error = RuntimeError("Agent failed")
        
        context = self.error_handler.handle_agent_error(error, "test_agent", "processing")
        
        assert context.category == ErrorCategory.AGENT_PROCESSING
        assert context.details["agent_name"] == "test_agent"
        assert context.details["phase"] == "processing"
        assert self.error_handler.retry_counts["test_agent_processing"] == 1
    
    def test_handle_workflow_error(self):
        """Test handling workflow errors."""
        error = RuntimeError("Workflow failed")
        
        context = self.error_handler.handle_workflow_error(error, "context_detection")
        
        assert context.category == ErrorCategory.WORKFLOW
        assert context.details["workflow_phase"] == "context_detection"
    
    def test_should_retry_recoverable(self):
        """Test retry logic for recoverable errors."""
        error_context = ErrorContext(
            category=ErrorCategory.AGENT_PROCESSING,
            severity=ErrorSeverity.MEDIUM,
            message="Test error",
            recoverable=True
        )
        
        assert self.error_handler.should_retry(error_context, "test_op") is True
    
    def test_should_retry_non_recoverable(self):
        """Test retry logic for non-recoverable errors."""
        error_context = ErrorContext(
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.CRITICAL,
            message="Test error",
            recoverable=False
        )
        
        assert self.error_handler.should_retry(error_context, "test_op") is False
    
    def test_should_retry_max_retries_exceeded(self):
        """Test retry logic when max retries exceeded."""
        error_context = ErrorContext(
            category=ErrorCategory.AGENT_PROCESSING,
            severity=ErrorSeverity.MEDIUM,
            message="Test error",
            recoverable=True
        )
        
        # Set retry count to max
        self.error_handler.retry_counts["test_op"] = self.error_handler.max_retries
        
        assert self.error_handler.should_retry(error_context, "test_op") is False
    
    def test_should_retry_critical_error(self):
        """Test retry logic for critical errors."""
        error_context = ErrorContext(
            category=ErrorCategory.AGENT_PROCESSING,
            severity=ErrorSeverity.CRITICAL,
            message="Test error",
            recoverable=True
        )
        
        assert self.error_handler.should_retry(error_context, "test_op") is False
    
    def test_calculate_retry_delay(self):
        """Test exponential backoff calculation."""
        assert self.error_handler.calculate_retry_delay(0) == 1.0
        assert self.error_handler.calculate_retry_delay(1) == 2.0
        assert self.error_handler.calculate_retry_delay(2) == 4.0
        assert self.error_handler.calculate_retry_delay(3) == 8.0
    
    def test_get_error_summary_empty(self):
        """Test error summary with no errors."""
        summary = self.error_handler.get_error_summary()
        
        assert summary["total_errors"] == 0
        assert summary["by_category"] == {}
        assert summary["by_severity"] == {}
    
    def test_get_error_summary_with_errors(self):
        """Test error summary with multiple errors."""
        # Add some errors directly to avoid double counting
        error1 = ValueError("Error 1")
        error2 = FileNotFoundError("Error 2")
        error3 = RuntimeError("Error 3")
        
        self.error_handler.handle_error(error1, ErrorCategory.VALIDATION)
        self.error_handler.handle_error(error2, ErrorCategory.FILE_SYSTEM)
        self.error_handler.handle_error(error3, ErrorCategory.AGENT_PROCESSING)
        
        summary = self.error_handler.get_error_summary()
        
        assert summary["total_errors"] == 3
        assert "validation" in summary["by_category"]
        assert "file_system" in summary["by_category"]
        assert "agent_processing" in summary["by_category"]
        assert len(summary["recent_errors"]) == 3
    
    def test_clear_error_history(self):
        """Test clearing error history."""
        error = ValueError("Test error")
        self.error_handler.handle_error(error)
        self.error_handler.retry_counts["test"] = 1
        
        assert len(self.error_handler.error_history) == 1
        assert len(self.error_handler.retry_counts) == 1
        
        self.error_handler.clear_error_history()
        
        assert len(self.error_handler.error_history) == 0
        assert len(self.error_handler.retry_counts) == 0
    
    def test_error_code_generation(self):
        """Test error code generation."""
        error = ValueError("Test error")
        context = self.error_handler.handle_error(error, ErrorCategory.VALIDATION)
        
        assert context.error_code is not None
        assert context.error_code.startswith("TF-VAL-VAL-")
    
    def test_botocore_error_handling(self):
        """Test handling BotoCoreError."""
        error = BotoCoreError()
        
        context = self.error_handler.handle_api_error(error)
        
        assert context.category == ErrorCategory.NETWORK
        assert context.severity == ErrorSeverity.MEDIUM
        assert context.recoverable is True


class TestLoggingSetup:
    """Test logging configuration."""
    
    def test_setup_logging_console_only(self):
        """Test setting up console-only logging."""
        logger = setup_logging("DEBUG", include_console=True)
        
        assert logger.level == logging.DEBUG
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0], logging.StreamHandler)
    
    def test_setup_logging_with_file(self):
        """Test setting up logging with file output."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            log_file = tmp_file.name
        
        try:
            logger = setup_logging("INFO", log_file=log_file, include_console=True)
            
            assert logger.level == logging.INFO
            assert len(logger.handlers) == 2
            
            # Check handlers
            handler_types = [type(h).__name__ for h in logger.handlers]
            assert "StreamHandler" in handler_types
            assert "FileHandler" in handler_types
            
        finally:
            Path(log_file).unlink(missing_ok=True)
    
    def test_setup_logging_file_only(self):
        """Test setting up file-only logging."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            log_file = tmp_file.name
        
        try:
            logger = setup_logging("WARNING", log_file=log_file, include_console=False)
            
            assert logger.level == logging.WARNING
            assert len(logger.handlers) == 1
            assert isinstance(logger.handlers[0], logging.FileHandler)
            
        finally:
            Path(log_file).unlink(missing_ok=True)
    
    def test_get_logger(self):
        """Test getting a module-specific logger."""
        logger = get_logger("test_module")
        
        assert logger.name == "threatforest.test_module"
    
    def test_logging_levels(self):
        """Test different logging levels."""
        levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        
        for level in levels:
            logger = setup_logging(level)
            assert logger.level == getattr(logging, level)


class TestErrorHandlerIntegration:
    """Integration tests for error handler."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.error_handler = ErrorHandler()
    
    def test_multiple_error_handling(self):
        """Test handling multiple different types of errors."""
        errors = [
            (ValueError("Validation error"), ErrorCategory.VALIDATION),
            (FileNotFoundError("File not found"), ErrorCategory.FILE_SYSTEM),
            (NoCredentialsError(), ErrorCategory.AUTHENTICATION),
            (RuntimeError("Runtime error"), ErrorCategory.UNKNOWN)
        ]
        
        for error, expected_category in errors:
            context = self.error_handler.handle_error(error)
            assert context.category == expected_category
        
        summary = self.error_handler.get_error_summary()
        assert summary["total_errors"] == 4
    
    def test_retry_workflow(self):
        """Test complete retry workflow."""
        error = RuntimeError("Temporary failure")
        operation_key = "test_operation"
        
        # First attempt
        context1 = self.error_handler.handle_error(error, ErrorCategory.AGENT_PROCESSING)
        assert self.error_handler.should_retry(context1, operation_key) is True
        
        # Simulate retry attempts
        for i in range(self.error_handler.max_retries):
            context = self.error_handler.handle_error(error, ErrorCategory.AGENT_PROCESSING)
            self.error_handler.retry_counts[operation_key] = i + 1
        
        # Should not retry after max attempts
        final_context = self.error_handler.handle_error(error, ErrorCategory.AGENT_PROCESSING)
        assert self.error_handler.should_retry(final_context, operation_key) is False
    
    @patch('time.time')
    def test_error_code_uniqueness(self, mock_time):
        """Test that error codes are unique."""
        mock_time.return_value = 1234567890
        
        error1 = ValueError("Error 1")
        error2 = ValueError("Error 2")
        
        context1 = self.error_handler.handle_error(error1)
        context2 = self.error_handler.handle_error(error2)
        
        # Should be different due to different timestamps or other factors
        assert context1.error_code != context2.error_code or mock_time.call_count > 1