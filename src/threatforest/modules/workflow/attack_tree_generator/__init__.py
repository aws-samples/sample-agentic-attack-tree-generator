"""Attack Tree Generator Tool - Modular Implementation

This package provides a modular implementation of the AttackTreeGeneratorTool,
breaking down the monolithic tool into specialized modules:

- context_builder: Build enhanced context for prompts
- state_manager: Track generation state and skip completed threats
- mermaid_processor: Extract and clean Mermaid diagrams
- tree_validator: Validate attack tree structure
- tree_generator: Core generation logic with Strands (SYNCHRONOUS)
- tool: Main orchestrator class (SYNCHRONOUS)

Key improvements over original:
- Fully synchronous (no async/await complexity)
- No manual rate limiting (Strands handles it)
- No manual retry logic (Strands handles it)
- Modular, testable architecture

Usage:
    from ..workflow.attack_tree_generator import AttackTreeGeneratorTool
    
    tool = AttackTreeGeneratorTool()
    result = tool.execute(threat_statements, extracted_info, bedrock_model)
"""

from .tool import AttackTreeGeneratorTool

__all__ = ['AttackTreeGeneratorTool']
