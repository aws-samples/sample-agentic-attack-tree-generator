"""
ThreatForest - Agentic AI application for automated attack tree generation.

A multi-agent system that analyzes application context files and generates
Mermaid-formatted attack trees enhanced with STIX threat intelligence.
"""

__version__ = "0.1.0"
__author__ = "ThreatForest Team"

# Lazy imports to avoid circular dependencies
def __getattr__(name):
    if name == 'ContextInformation':
        from .models import ContextInformation
        return ContextInformation
    elif name == 'ThreatStatement':
        from .models import ThreatStatement
        return ThreatStatement
    elif name == 'AttackTree':
        from .models import AttackTree
        return AttackTree
    elif name == 'TTCMapping':
        from .models import TTCMapping
        return TTCMapping
    elif name == 'ConfigManager':
        from .config import ConfigManager
        return ConfigManager
    elif name == 'main':
        from .cli import main
        return main
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

__all__ = [
    "ContextInformation",
    "ThreatStatement", 
    "AttackTree",
    "TTCMapping",
    "ConfigManager",
    "main",
]