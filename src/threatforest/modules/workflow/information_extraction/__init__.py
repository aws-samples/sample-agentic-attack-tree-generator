"""Information Extraction Tool - Modular Implementation

This package provides a modular implementation of the InformationExtractionTool,
breaking down the monolithic tool into specialized, single-responsibility modules:

- text_utils: Text parsing utilities
- file_utils: File operation utilities  
- threat_formatter: Threat output formatting
- threat_parser: Threat parsing from various formats
- project_extractor: Project metadata extraction (LLM)
- threat_generator: Threat generation and reformatting (LLM)
- tool: Main orchestrator class

Usage:
    from ..workflow.information_extraction import InformationExtractionTool
    
    tool = InformationExtractionTool()
    result = tool.execute(context_files, bedrock_model)
"""

from .tool import InformationExtractionTool

__all__ = ['InformationExtractionTool']
