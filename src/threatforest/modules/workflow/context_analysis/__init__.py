"""Context Analysis Tool - Modular Implementation

Clean modular implementation with:
- file_categorizer: File type categorization and threat file detection
- context_extractor: Enhanced context extraction using Strands for READMEs/diagrams
- summary_generator: Human-readable summary generation
- tool: Main orchestrator coordinating all modules

Note: Threat file parsing is handled by ParserAgent in the extraction stage to avoid duplication.

Already synchronous, already uses Strands, already uses FileDiscovery.
Main benefits: Better organization, testability, and reusability.

Usage:
    from threatforest.modules.workflow.context_analysis import ContextAnalysisTool
    
    tool = ContextAnalysisTool()
    result = tool.run(project_path)
"""

from .tool import ContextAnalysisTool

__all__ = ['ContextAnalysisTool']
