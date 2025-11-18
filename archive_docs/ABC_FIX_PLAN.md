# ABC Conflict Fix - Action Plan

**Issue:** Dual ABC inheritance conflict
**Solution:** Remove Tool, keep BaseAgent

## Changes Required (3 tools)

### 1. ContextAnalysisTool
**File:** `src/modules/tools/context_analysis_tool/tool.py`

```python
# Change line 12 from:
class ContextAnalysisTool(BaseAgent, Tool):

# To:
class ContextAnalysisTool(BaseAgent):

# Change lines 15-18 from:
    def __init__(self):
        Tool.__init__(
            self,
            name="context_analysis",

# To:
    def __init__(self):
        self.name = "context_analysis"
        self.description = "Discover and analyze context files including threat models, READMEs, and architecture diagrams"
```

### 2. InformationExtractionTool
**File:** `src/modules/tools/information_extraction_tool/tool.py`

Same pattern - remove Tool inheritance, add properties.

### 3. AttackTreeGeneratorTool
**File:** `src/modules/tools/attack_tree_generator_tool/tool.py`

Same pattern - remove Tool inheritance, add properties.

## Commands to Execute

```bash
cd src/modules/tools

# For each tool.py:
# 1. Change class declaration to remove ", Tool"
# 2. Replace Tool.__init__() with self.name/self.description
# 3. Remove "tool" from imports
```

## Result

All tools will be pure BaseAgent implementations with `run()` method, satisfying the ABC requirement properly.

**Estimated time:** 3 changes, 2 minutes total
