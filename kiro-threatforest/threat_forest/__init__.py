"""
ThreatForest - Automated Attack Tree Generation Tool

A Python application that generates attack trees from threat statements
found in application context files, enhanced with MITRE ATT&CK mappings.
"""

__version__ = "0.1.0"
__author__ = "ThreatForest Team"

from .models import ApplicationInfo, ThreatStatement, AttackStep, AttackTree, STIXTechnique
from .exceptions import ThreatForestError, FileProcessingError, LLMError, STIXProcessingError

__all__ = [
    "ApplicationInfo",
    "ThreatStatement", 
    "AttackStep",
    "AttackTree",
    "STIXTechnique",
    "ThreatForestError",
    "FileProcessingError",
    "LLMError", 
    "STIXProcessingError"
]