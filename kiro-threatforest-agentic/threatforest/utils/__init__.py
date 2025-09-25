"""
Utility modules for ThreatForest.
"""

# Lazy imports to avoid circular dependencies
def __getattr__(name):
    if name == 'BedrockClient':
        from .bedrock_client import BedrockClient
        return BedrockClient
    elif name == 'BedrockResponse':
        from .bedrock_client import BedrockResponse
        return BedrockResponse
    elif name == 'BedrockClientError':
        from .bedrock_client import BedrockClientError
        return BedrockClientError
    elif name == 'ModelInfo':
        from .bedrock_client import ModelInfo
        return ModelInfo
    elif name == 'STIXProcessor':
        from .stix_processor import STIXProcessor
        return STIXProcessor
    elif name == 'STIXTechnique':
        from .stix_processor import STIXTechnique
        return STIXTechnique
    elif name == 'STIXTactic':
        from .stix_processor import STIXTactic
        return STIXTactic
    elif name == 'STIXSearchResult':
        from .stix_processor import STIXSearchResult
        return STIXSearchResult
    elif name == 'STIXProcessorError':
        from .stix_processor import STIXProcessorError
        return STIXProcessorError
    elif name == 'FileManager':
        from .file_manager import FileManager
        return FileManager
    elif name == 'OutputSummary':
        from .file_manager import OutputSummary
        return OutputSummary
    elif name == 'FileManagerError':
        from .file_manager import FileManagerError
        return FileManagerError
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

__all__ = [
    "BedrockClient",
    "BedrockResponse", 
    "BedrockClientError",
    "ModelInfo",
    "STIXProcessor",
    "STIXTechnique",
    "STIXTactic",
    "STIXSearchResult",
    "STIXProcessorError",
    "FileManager",
    "OutputSummary",
    "FileManagerError",
]