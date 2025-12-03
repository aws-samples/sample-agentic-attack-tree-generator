"""Summary Generator Tool - Modular Implementation

Clean modular implementation with:
- report_formatters: All formatting helper methods (static)
- file_generators: File creation logic (main summary, attack trees, JSON)
- tool: Main orchestrator (fully synchronous)

Key improvement: Removed async/await (execute is now synchronous).
No LLM calls needed - pure report generation from existing data.

Usage:
    from threatforest.modules.tools.summary_generator_tool import SummaryGeneratorTool
    
    tool = SummaryGeneratorTool()
    result = tool.execute(attack_trees, extracted_info, output_dir)
"""

from .tool import SummaryGeneratorTool

__all__ = ['SummaryGeneratorTool']
