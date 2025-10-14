"""Tests for error handling (Tasks 2.1-2.3)"""
import unittest
from threatforest.core.errors import (
    ErrorSeverity, ThreatForestError, BedrockError, ValidationError,
    FileOperationError, StateError, ConfigurationError
)
from threatforest.core.error_handler import ErrorHandler


class TestErrorTypes(unittest.TestCase):
    """Test error type definitions"""
    
    def test_error_severity_enum(self):
        """Test ErrorSeverity enum values"""
        self.assertEqual(ErrorSeverity.CRITICAL.value, "critical")
        self.assertEqual(ErrorSeverity.HIGH.value, "high")
        self.assertEqual(ErrorSeverity.MEDIUM.value, "medium")
        self.assertEqual(ErrorSeverity.LOW.value, "low")
    
    def test_threatforest_error_dataclass(self):
        """Test ThreatForestError dataclass"""
        error = ThreatForestError(
            code="TEST_ERROR",
            message="Test error message",
            severity=ErrorSeverity.HIGH,
            context={"key": "value"},
            recoverable=True,
            recovery_suggestion="Test suggestion"
        )
        
        self.assertEqual(error.code, "TEST_ERROR")
        self.assertEqual(error.message, "Test error message")
        self.assertEqual(error.severity, ErrorSeverity.HIGH)
        self.assertTrue(error.recoverable)
    
    def test_bedrock_error_exception(self):
        """Test BedrockError exception"""
        error = BedrockError("Bedrock API failed", {"model": "test"})
        
        self.assertEqual(error.message, "Bedrock API failed")
        self.assertEqual(error.context["model"], "test")
    
    def test_validation_error_exception(self):
        """Test ValidationError exception"""
        error = ValidationError("Invalid input", field="project_path")
        
        self.assertEqual(error.message, "Invalid input")
        self.assertEqual(error.field, "project_path")


class TestErrorHandler(unittest.TestCase):
    """Test ErrorHandler class"""
    
    def test_handle_bedrock_throttling(self):
        """Test handling Bedrock throttling errors"""
        error = Exception("ThrottlingException: Rate exceeded")
        result = ErrorHandler.handle_bedrock_error(error)
        
        self.assertEqual(result.code, "BEDROCK_THROTTLED")
        self.assertEqual(result.severity, ErrorSeverity.HIGH)
        self.assertTrue(result.recoverable)
        self.assertIn("backoff", result.recovery_suggestion)
    
    def test_handle_bedrock_auth_error(self):
        """Test handling Bedrock authentication errors"""
        error = Exception("AccessDeniedException: Not authorized")
        result = ErrorHandler.handle_bedrock_error(error)
        
        self.assertEqual(result.code, "BEDROCK_AUTH_FAILED")
        self.assertEqual(result.severity, ErrorSeverity.CRITICAL)
        self.assertFalse(result.recoverable)
    
    def test_handle_validation_error(self):
        """Test handling validation errors"""
        error = ValidationError("Invalid path", field="project_path")
        result = ErrorHandler.handle_validation_error(error)
        
        self.assertEqual(result.code, "VALIDATION_ERROR")
        self.assertEqual(result.severity, ErrorSeverity.MEDIUM)
        self.assertTrue(result.recoverable)
        self.assertIn("field", result.context)
    
    def test_handle_file_error(self):
        """Test handling file operation errors"""
        error = FileOperationError("File not found", file_path="/test/path")
        result = ErrorHandler.handle_file_error(error)
        
        self.assertEqual(result.code, "FILE_ERROR")
        self.assertEqual(result.severity, ErrorSeverity.MEDIUM)
        self.assertTrue(result.recoverable)
        self.assertIn("file_path", result.context)
    
    def test_error_to_dict(self):
        """Test error serialization to dictionary"""
        error = ThreatForestError(
            code="TEST_ERROR",
            message="Test message",
            severity=ErrorSeverity.HIGH,
            context={"key": "value"},
            recoverable=True,
            recovery_suggestion="Test suggestion"
        )
        
        result = ErrorHandler.to_dict(error)
        
        self.assertIn("error", result)
        self.assertEqual(result["error"]["code"], "TEST_ERROR")
        self.assertEqual(result["error"]["severity"], "high")
        self.assertTrue(result["error"]["recoverable"])


if __name__ == '__main__':
    unittest.main()
