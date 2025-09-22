"""
Custom exception classes for ThreatForest application.
"""


class ThreatForestError(Exception):
    """Base exception class for ThreatForest application."""
    pass


class FileProcessingError(ThreatForestError):
    """Raised when file processing operations fail."""
    pass


class LLMError(ThreatForestError):
    """Raised when LLM API operations fail."""
    pass


class STIXProcessingError(ThreatForestError):
    """Raised when STIX data processing fails."""
    pass


class MermaidValidationError(ThreatForestError):
    """Raised when Mermaid diagram validation fails."""
    pass


class ConfigurationError(ThreatForestError):
    """Raised when configuration is invalid or missing."""
    pass