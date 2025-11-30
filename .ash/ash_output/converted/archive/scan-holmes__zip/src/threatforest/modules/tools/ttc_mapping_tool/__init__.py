"""TTC Mapping Tool - Modular Implementation

Clean modular implementation with:
- matcher_initializer: Initialize local or Neptune embedding matcher
- mapping_processor: Process TTC mappings with progress tracking
- tool: Main orchestrator (fully synchronous)

Key improvements:
- Removed async/await (execute is now synchronous)
- Better code organization
- Separated initialization from processing logic

Usage:
    from threatforest.modules.tools.ttc_mapping_tool import TTCMappingTool
    
    tool = TTCMappingTool(threshold=0.8)
    result = tool.execute(attack_trees, bedrock_model, aws_profile=profile)
"""

from .tool import TTCMappingTool

__all__ = ['TTCMappingTool']
