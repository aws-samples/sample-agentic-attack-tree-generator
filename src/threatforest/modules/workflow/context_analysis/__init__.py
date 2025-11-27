"""Context Analysis Tool - Modular Implementation

Clean modular implementation with:
- file_categorizer: File type categorization and threat detection
- threat_extractor: Threat extraction with JQ/Python fallback
- context_extractor: Enhanced context extraction using Strands
- summary_generator: Human-readable summary generation
- tool: Main orchestrator coordinating all modules

Already synchronous, already uses Strands, already uses FileDiscovery.
Main benefits: Better organization, testability, and reusability.

Usage:
    from threatforest.modules.tools.context_analysis_tool import ContextAnalysisTool
    
    tool = ContextAnalysisTool()
    result = tool.execute(project_path, bedrock_model)
"""

from .tool import ContextAnalysisTool

__all__ = ['ContextAnalysisTool']
