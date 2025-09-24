"""
ThreatForest - Agentic AI application for automated attack tree generation.

A multi-agent system that analyzes application context files and generates
Mermaid-formatted attack trees enhanced with STIX threat intelligence.
"""

__version__ = "0.1.0"
__author__ = "ThreatForest Team"

from .models import ContextInformation, ThreatStatement, AttackTree, TTCMapping
from .config import ConfigManager
from .cli import main

__all__ = [
    "ContextInformation",
    "ThreatStatement", 
    "AttackTree",
    "TTCMapping",
    "ConfigManager",
    "main",
]