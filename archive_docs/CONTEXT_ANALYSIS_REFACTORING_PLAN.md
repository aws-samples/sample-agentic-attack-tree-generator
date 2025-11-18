# ContextAnalysisTool Refactoring Plan

## Overview

Complete modularization plan for `context_analysis_tool.py` (~350 lines) into 6 focused modules.

## Completed Refactorings

✅ **InformationExtractionTool** - 8 modules, fully modular
✅ **AttackTreeGeneratorTool** - 7 modules, synchronous

## Target Structure

```
src/modules/tools/context_analysis_tool/
├── __init__.py              # Exports ContextAnalysisTool
├── tool.py                  # Main orchestrator (~60 lines)
├── file_categorizer.py      # File categorization (~80 lines)
├── threat_extractor.py      # Threat extraction with JQ (~120 lines)
├── context_extractor.py     # Enhanced context with Strands (~80 lines)
└── summary_generator.py     # Summary generation (~70 lines)
```

## Module Specifications

### 1. file_categorizer.py (~80 lines)

```python
"""File categorization utilities"""
from pathlib import Path
from typing import Dict, List

class FileCategorizer:
    """Categorizes project files by type"""
    
    def __init__(self, logger):
        self.logger = logger
        self.threat_keywords = ['threat', 'risk', 'vulnerability', 'attack', 'security']
    
    def categorize_file(self, file_path: Path, context_files: Dict[str, List]) -> None:
        """Categorize a file into appropriate category"""
        # Implementation: _categorize_file from original
    
    def contains_threat_statements(self, file_path: Path) -> bool:
        """Check if file contains threat statements"""
        # Implementation: _contains_threat_statements from original
    
    def is_text_file(self, file_path: str) -> bool:
        """Check if file is processable text"""
        # Implementation: _is_text_file from original
    
    def is_binary_file(self, file_path: str) -> bool:
        """Check if file is binary"""
        # Implementation: _is_binary_file from original
```

### 2. threat_extractor.py (~120 lines)

```python
"""Threat extraction with JQ and Python fallback"""
import json
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List

class ThreatExtractor:
    """Extracts threats from various formats"""
    
    def __init__(self, logger):
        self.logger = logger
    
    def process_threat_models(self, threat_files: List[str]) -> Dict[str, Any]:
        """Process all threat model files"""
        # Implementation: _process_threat_models from original
    
    def extract_threats_enhanced(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Extract using JQ or Python fallback"""
        # Implementation: _extract_threats_enhanced from original
    
    def python_extract(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Python fallback extraction"""
        # Implementation: _python_extract from original
    
    def extract_threatcomposer(self, data: Dict) -> Dict[str, Any]:
        """Extract ThreatComposer format"""
        # Implementation: _extract_threatcomposer from original
    
    def detect_format(self, file_path: str) -> str:
        """Detect threat file format"""
        # Implementation: _detect_format from original
```

### 3. context_extractor.py (~80 lines)

```python
"""Enhanced context extraction using Strands Agent"""
import json
from typing import Dict, Any, Optional
from pathlib import Path
from ...core import BaseAgent

class ContextExtractor(BaseAgent):
    """Extracts enhanced context using LLM"""
    
    def __init__(self, logger):
        self.logger = logger
    
    def extract_enhanced_context(self, context_files: Dict[str, Any],
                                bedrock_model: str,
                                aws_profile: Optional[str] = None) -> Dict[str, Any]:
        """Extract enhanced context via Strands"""
        # Implementation: _extract_enhanced_context_via_bedrock from original
        # Uses Strands agent with context-extraction.md prompt
    
    def parse_context_from_text(self, text: str) -> Dict[str, Any]:
        """Parse context from text response"""
        # Implementation: _parse_context_from_text from original
```

### 4. summary_generator.py (~70 lines)

```python
"""Summary generation for context analysis results"""
from typing import Dict, Any

class SummaryGenerator:
    """Generates human-readable summaries"""
    
    @staticmethod
    def generate_summary(threat_analysis: Dict[str, Any],
                        parsed_files: Dict[str, Any],
                        discovered_files: Dict[str, Any] = None) -> str:
        """Generate enhanced summary with threat focus"""
        # Implementation: _generate_enhanced_summary from original
```

### 5. tool.py (~60 lines)

```python
"""Main Context Analysis Tool - Orchestrates discovery and analysis"""
from typing import Dict, Any, Optional
from ...utils.logger import ThreatForestLogger
from ...core import Tool, tool, FileDiscovery, BaseAgent
from .file_categorizer import FileCategorizer
from .threat_extractor import ThreatExtractor
from .context_extractor import ContextExtractor
from .summary_generator import SummaryGenerator

class ContextAnalysisTool(BaseAgent, Tool):
    """Enhanced context analysis with modular architecture"""
    
    def __init__(self):
        Tool.__init__(
            self,
            name="context_analysis",
            description="Discover and analyze context files"
        )
        self.logger = ThreatForestLogger.get_logger(self.__class__.__name__)
        
        # Initialize modules
        self.categorizer = FileCategorizer(self.logger)
        self.threat_extractor = ThreatExtractor(self.logger)
        self.context_extractor = ContextExtractor(self.logger)
        self.summary_generator = SummaryGenerator()
    
    def execute(self, project_path: str, bedrock_model: str,
               aws_profile: Optional[str] = None) -> Dict[str, Any]:
        """Execute enhanced context analysis"""
        # Use FileDiscovery
        discovered = FileDiscovery.discover(project_path)
        
        # Build context files structure
        context_files = self._build_context_structure(discovered)
        
        # Process threat models
        threat_analysis = self.threat_extractor.process_threat_models(
            discovered.threat_models
        )
        
        # Parse other files
        parsed_files = self._parse_files(context_files)
        
        # Extract enhanced context via Strands
        enhanced_context = self.context_extractor.extract_enhanced_context(
            context_files, bedrock_model, aws_profile
        )
        
        # Generate summary
        summary = self.summary_generator.generate_summary(
            threat_analysis, parsed_files, context_files
        )
        
        return {
            "project_path": project_path,
            "discovered_files": context_files,
            "threat_analysis": threat_analysis,
            "parsed_content": parsed_files,
            "summary": summary,
            "enhanced_context": enhanced_context
        }
```

### 6. __init__.py (~20 lines)

```python
"""Context Analysis Tool - Modular Implementation

Modular implementation with:
- file_categorizer: File type categorization
- threat_extractor: Threat extraction with JQ/Python
- context_extractor: Enhanced context with Strands (LLM)
- summary_generator: Human-readable summaries
- tool: Main orchestrator

Already synchronous, already uses Strands, already uses FileDiscovery.
Main benefit: Better separation of concerns and testability.
"""

from .tool import ContextAnalysisTool

__all__ = ['ContextAnalysisTool']
```

## Implementation Steps

1. Create `context_analysis_tool/` directory ✅
2. Extract file categorization → `file_categorizer.py`
3. Extract threat extraction → `threat_extractor.py`
4. Extract context extraction → `context_extractor.py`
5. Extract summary generation → `summary_generator.py`
6. Create main orchestrator → `tool.py`
7. Create package exports → `__init__.py`
8. Backup original file → `context_analysis_tool.py.backup`
9. Test imports and functionality

## Key Differences from Other Tools

**Already Good:**
- ✅ Synchronous execution (no async removal needed)
- ✅ Uses Strands Agent (already migrated)
- ✅ Uses FileDiscovery (modern approach)

**What Refactoring Provides:**
- 🔄 Better code organization
- 🔄 Easier testing (unit test each module)
- 🔄 Reusable components
- 🔄 Clearer responsibilities

## Benefits

| Aspect | Before | After |
|--------|--------|-------|
| Files | 1 | 6 |
| Avg Lines/File | 350 | 60-120 |
| Responsibilities | Mixed | Single per module |
| Testability | Hard | Easy (unit tests) |
| Reusability | Low | High |

## Backward Compatibility

100% compatible - same import path:
```python
from src.modules.tools.context_analysis_tool import ContextAnalysisTool
```

## Status

- **InformationExtractionTool**: ✅ Complete (8 modules)
- **AttackTreeGeneratorTool**: ✅ Complete (7 modules)  
- **ContextAnalysisTool**: 📝 Plan documented, ready to implement

## Next Steps

When ready to implement:
1. Toggle to Act mode
2. Create 5 modules as specified above
3. Create main tool.py orchestrator
4. Test imports and functionality
5. Verify backward compatibility

Total time estimate: 10-15 minutes
