# Task 1.4: Implementation Plan - Single Model Usage

**Status**: 📋 Ready to Execute  
**Date**: October 22, 2025

## Objective

Ensure the user-selected model during initial configuration is the ONLY model used throughout the entire application.

---

## Changes Required

### 1. Create Centralized Model Configuration

**File**: `src/config/models.py` (NEW)

```python
"""Centralized Bedrock model configuration"""

class ModelConfig:
    """Model configuration for ThreatForest application"""
    
    # Available models for user selection in UI
    AVAILABLE_MODELS = [
        "us.anthropic.claude-sonnet-4-20250514-v1:0",
        "us.anthropic.claude-opus-4-1-20250805-v1:0",
        "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "anthropic.claude-3-5-haiku-20241022-v1:0",
        "anthropic.claude-3-opus-20240229-v1:0",
        "anthropic.claude-3-haiku-20240307-v1:0",
        "amazon.titan-text-premier-v1:0",
        "amazon.titan-text-express-v1",
        "meta.llama3-2-90b-instruct-v1:0",
        "meta.llama3-2-11b-instruct-v1:0"
    ]
    
    # Default model (used if user doesn't select)
    DEFAULT_MODEL = "us.anthropic.claude-sonnet-4-20250514-v1:0"
```

---

### 2. Update TTCMappingTool - Remove Default Parameter

**File**: `src/modules/tools/ttc_mapping_tool.py:30`

**Before**:
```python
async def execute(self, attack_trees: Dict[str, Any], 
                 bedrock_model: str = "us.anthropic.claude-sonnet-4-20250514-v1:0",
                 aws_profile: Optional[str] = None,
```

**After**:
```python
async def execute(self, attack_trees: Dict[str, Any], 
                 bedrock_model: str,  # REQUIRED - no default
                 aws_profile: Optional[str] = None,
```

---

### 3. Update ContextAnalysisTool - Add Model Parameter

**File**: `src/modules/tools/context_analysis_tool.py`

**Change 1 - Update execute signature (line ~145)**:

**Before**:
```python
async def execute(self, project_path: str) -> Dict[str, Any]:
```

**After**:
```python
async def execute(self, project_path: str, bedrock_model: str) -> Dict[str, Any]:
```

**Change 2 - Remove hardcoded fallback (line ~459)**:

**Before**:
```python
model_id = context_files.get('model_id', 'us.anthropic.claude-sonnet-4-20250514-v1:0')
```

**After**:
```python
model_id = bedrock_model  # Use provided model
```

---

### 4. Update Orchestrator - Pass Model to ContextAnalysisTool

**File**: `src/strands_agent.py`

**Find the context analysis step** (search for `context_analysis_tool.execute`):

**Before**:
```python
result = await context_analysis_tool.execute(
    project_path=project_path
)
```

**After**:
```python
result = await context_analysis_tool.execute(
    project_path=project_path,
    bedrock_model=self.config.bedrock_model  # ADD THIS
)
```

---

### 5. Update SetupTool - Use Centralized Model List

**File**: `src/modules/tools/setup_tool.py:19-29`

**Before**:
```python
class SetupTool(Tool):
    """Tool for setting up ThreatForest environment"""
    
    AVAILABLE_MODELS = [
        "us.anthropic.claude-sonnet-4-20250514-v1:0",
        "us.anthropic.claude-opus-4-1-20250805-v1:0",
        # ... more models
    ]
```

**After**:
```python
from config.models import ModelConfig

class SetupTool(Tool):
    """Tool for setting up ThreatForest environment"""
    
    AVAILABLE_MODELS = ModelConfig.AVAILABLE_MODELS  # Use centralized list
```

---

### 6. Update ThreatForestConfig - Use Centralized Default

**File**: `src/strands_agent.py:25`

**Before**:
```python
bedrock_model: str = "us.anthropic.claude-sonnet-4-20250514-v1:0"
```

**After**:
```python
from config.models import ModelConfig

@dataclass
class ThreatForestConfig:
    bedrock_model: str = ModelConfig.DEFAULT_MODEL
```

---

## Validation Steps

### 1. Search for Remaining Hardcoded Models
```bash
grep -rn "claude-sonnet\|claude-opus\|claude-haiku" src/ --include="*.py" | grep -v "config/models.py"
```
**Expected**: Only imports from config/models.py

### 2. Verify All Tools Receive Model Parameter
```bash
grep -A 3 "async def execute" src/modules/tools/*.py | grep "bedrock_model"
```
**Expected**: All tools have bedrock_model parameter

### 3. Test Model Propagation
- Start application
- Select different model in UI
- Verify all tools use selected model (check logs)

---

## Testing Checklist

- [ ] Create config/models.py
- [ ] Update TTCMappingTool (remove default)
- [ ] Update ContextAnalysisTool (add parameter, remove fallback)
- [ ] Update orchestrator (pass model to context analysis)
- [ ] Update SetupTool (use centralized list)
- [ ] Update ThreatForestConfig (use centralized default)
- [ ] Run validation searches
- [ ] Test with different models
- [ ] Verify logs show consistent model usage

---

## Success Criteria

✅ User selects ONE model in UI  
✅ That model is used by ALL tools  
✅ No hardcoded model defaults in any tool  
✅ No hardcoded model fallbacks  
✅ Centralized model list for UI selection  
✅ All tests passing

---

## Files Modified Summary

1. **NEW**: `src/config/models.py`
2. **MODIFIED**: `src/modules/tools/ttc_mapping_tool.py`
3. **MODIFIED**: `src/modules/tools/context_analysis_tool.py`
4. **MODIFIED**: `src/strands_agent.py`
5. **MODIFIED**: `src/modules/tools/setup_tool.py`

**Total**: 1 new file, 4 modified files
