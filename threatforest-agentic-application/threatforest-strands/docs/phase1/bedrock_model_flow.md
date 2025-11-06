# Bedrock Model Identification and Usage Flow

**Date**: October 22, 2025

## Overview

This document describes how Bedrock models are identified, configured, and used throughout the ThreatForest application.

---

## Model Flow Architecture

### 1. Model Configuration Entry Point

**Source**: `src/strands_agent.py:25`
```python
@dataclass
class ThreatForestConfig:
    bedrock_model: str = "us.anthropic.claude-sonnet-4-20250514-v1:0"  # Default
```

**Purpose**: 
- Defines default model for entire orchestrator
- Can be overridden when creating ThreatForestConfig instance
- Stored in ThreatForestState for workflow persistence

---

### 2. Model Propagation Through State

**Flow**: Config → State → Tools

```python
# strands_agent.py - State initialization
ThreatForestState(
    project_path=str(self.config.project_path),
    aws_profile=self.config.aws_profile,
    bedrock_model=self.config.bedrock_model  # Passed to state
)
```

**State Storage**:
- Model ID stored in ThreatForestState
- Persisted across workflow stages
- Available for resume functionality

---

### 3. Model Distribution to Tools

**Pattern**: Orchestrator passes model to each tool's execute() method

#### Example 1: Information Extraction Tool
```python
# strands_agent.py:175
result = await information_extraction_tool.execute(
    context_files=context_files,
    bedrock_model=self.config.bedrock_model,  # Passed explicitly
    aws_profile=self.config.aws_profile
)
```

#### Example 2: Attack Tree Generator Tool
```python
# strands_agent.py:256
result = await attack_tree_generator_tool.execute(
    threat_statements=threat_statements,
    extracted_info=extracted_info,
    bedrock_model=self.config.bedrock_model,  # Passed explicitly
    aws_profile=self.config.aws_profile
)
```

**Tool Signatures**:
- All tools receive `bedrock_model: str` parameter
- Tools pass model to BedrockInvoker for API calls

---

### 4. Model Usage in BedrockInvoker

**Source**: `src/modules/core/bedrock_invoker.py`

```python
async def invoke_with_retry(
    self,
    model_id: str,  # Receives model from tool
    prompt: str,
    aws_profile: Optional[str] = None,
    max_tokens: int = 65536,
    temperature: float = 0.7,
    system_prompt: str = ""
) -> str:
```

**Model ID Processing**:
1. Receives model ID string (e.g., "us.anthropic.claude-sonnet-4-20250514-v1:0")
2. Checks if cross-region inference profile (starts with 'us.' or 'eu.')
3. Converts to ARN format if needed:
   ```python
   if model_id.startswith('us.') or model_id.startswith('eu.'):
       model_id = f"arn:aws:bedrock:us-east-1::foundation-model/{model_id}"
   ```
4. Passes to Bedrock API via `invoke_model(modelId=model_id, ...)`

---

## Model Types and Formats

### Cross-Region Inference Profiles
**Format**: `{region}.{provider}.{model-name}`
**Examples**:
- `us.anthropic.claude-sonnet-4-20250514-v1:0`
- `us.anthropic.claude-opus-4-1-20250805-v1:0`

**Conversion**: Automatically converted to ARN format
```
arn:aws:bedrock:us-east-1::foundation-model/{model_id}
```

### Standard Model IDs
**Format**: `{provider}.{model-name}`
**Examples**:
- `anthropic.claude-3-5-sonnet-20241022-v2:0`
- `anthropic.claude-3-opus-20240229-v1:0`
- `amazon.titan-text-premier-v1:0`
- `meta.llama3-2-90b-instruct-v1:0`

**Usage**: Passed directly to Bedrock API without conversion

---

## Available Models List

**Source**: `src/modules/tools/setup_tool.py:19-29`

```python
AVAILABLE_MODELS = [
    # Cross-region inference profiles
    "us.anthropic.claude-sonnet-4-20250514-v1:0",
    "us.anthropic.claude-opus-4-1-20250805-v1:0",
    
    # Standard models
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "anthropic.claude-3-5-haiku-20241022-v1:0",
    "anthropic.claude-3-opus-20240229-v1:0",
    "anthropic.claude-3-haiku-20240307-v1:0",
    "amazon.titan-text-premier-v1:0",
    "amazon.titan-text-express-v1",
    "meta.llama3-2-90b-instruct-v1:0",
    "meta.llama3-2-11b-instruct-v1:0"
]
```

**Purpose**:
- Model selection in setup/configuration
- Validation of user-provided model IDs
- UI model picker options

---

## Model Usage by Tool

### Tools Receiving Model Parameter

1. **InformationExtractionTool**
   - Signature: `execute(context_files, bedrock_model, aws_profile, interactive)`
   - Uses model for threat extraction and generation

2. **AttackTreeGeneratorTool**
   - Signature: `execute(threat_statements, extracted_info, bedrock_model, aws_profile, existing_status)`
   - Uses model for attack tree generation

3. **TTCMappingTool**
   - Signature: `execute(attack_trees, bedrock_model, aws_profile)`
   - Default: `"us.anthropic.claude-sonnet-4-20250514-v1:0"` (line 30)
   - Uses model for TTC mapping

4. **SummaryGeneratorTool**
   - Signature: `execute(attack_trees, extracted_info, bedrock_model, aws_profile)`
   - Uses model for summary generation

### Tools NOT Receiving Model Parameter

1. **ContextAnalysisTool**
   - Signature: `execute(project_path)`
   - Uses hardcoded fallback: `'us.anthropic.claude-sonnet-4-20250514-v1:0'` (line 459)
   - **Issue**: No model parameter passed from orchestrator

2. **SetupTool**
   - Signature: `execute(project_path, aws_profile, bedrock_model)`
   - Uses model for validation only (not for API calls)

---

## Current Issues

### 1. Inconsistent Model Passing
- **ContextAnalysisTool** doesn't receive model from orchestrator
- Uses hardcoded fallback instead of configured model
- **Impact**: Context analysis always uses default model

### 2. Hardcoded Defaults in Tools
- **TTCMappingTool** has hardcoded default parameter
- **ContextAnalysisTool** has hardcoded fallback
- **Impact**: Tools may use different models than configured

### 3. Model List Maintenance
- **SetupTool** maintains static model list
- No central model registry
- **Impact**: Adding new models requires updating multiple files

### 4. No Model Validation
- No validation that model ID is valid
- No check if model is available in region
- **Impact**: Runtime errors if invalid model specified

---

## Desired Behavior

**Single Model Selection**: The user selects ONE model during initial configuration (via UI), and that model is used consistently throughout the entire application workflow.

**Requirements**:
1. User selects model once during setup
2. Selected model stored in configuration
3. All tools use the same selected model
4. No hardcoded fallbacks or defaults in tools
5. Model passed from orchestrator to every tool

---

## Recommendations

### 1. Remove All Hardcoded Model Defaults in Tools

**Current Issues**:
- TTCMappingTool has default parameter: `bedrock_model: str = "us.anthropic.claude-sonnet-4-20250514-v1:0"`
- ContextAnalysisTool has hardcoded fallback: `model_id = context_files.get('model_id', 'us.anthropic.claude-sonnet-4-20250514-v1:0')`

**Solution**: Make bedrock_model a required parameter (no defaults)
```python
# TTCMappingTool - REMOVE default
async def execute(self, attack_trees, bedrock_model: str, aws_profile):  # No default!
    
# ContextAnalysisTool - ADD model parameter
async def execute(self, project_path: str, bedrock_model: str):  # Add parameter!
```

### 2. Update Orchestrator to Pass Model to All Tools

**Fix ContextAnalysisTool** (currently missing):
```python
# strands_agent.py - Add bedrock_model parameter
result = await context_analysis_tool.execute(
    project_path=project_path,
    bedrock_model=self.config.bedrock_model  # ADD THIS
)
```

### 3. Centralize Model List for UI Selection Only

Create `src/config/models.py`:
```python
class ModelConfig:
    """Central model configuration - for UI selection only"""
    
    # Available models for user selection
    AVAILABLE_MODELS = [
        "us.anthropic.claude-sonnet-4-20250514-v1:0",
        "us.anthropic.claude-opus-4-1-20250805-v1:0",
        "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "anthropic.claude-3-5-haiku-20241022-v1:0",
        "anthropic.claude-3-opus-20240229-v1:0",
        "amazon.titan-text-premier-v1:0",
        "meta.llama3-2-90b-instruct-v1:0"
    ]
    
    # Default for ThreatForestConfig (if user doesn't select)
    DEFAULT_MODEL = "us.anthropic.claude-sonnet-4-20250514-v1:0"
```

**Usage**: Only for UI model picker and config default

### 4. Ensure Single Model Flow

**Flow**:
1. User selects model in UI → stored in ThreatForestConfig
2. Config model → passed to ThreatForestState
3. State model → passed to EVERY tool by orchestrator
4. Tools → use provided model (no fallbacks)
5. BedrockInvoker → uses model from tool

**No Exceptions**: Every tool must use the user-selected model

---

## Implementation Tasks

### Task 1.4: Create Centralized Model Configuration
- Create `src/config/models.py` with AVAILABLE_MODELS list
- Define DEFAULT_MODEL for config
- Remove model list from SetupTool

### Task 1.5: Remove All Hardcoded Model Defaults
**Files to Update**:
1. `src/modules/tools/ttc_mapping_tool.py:30` - Remove default parameter value
2. `src/modules/tools/context_analysis_tool.py:459` - Remove hardcoded fallback
3. `src/modules/tools/setup_tool.py:19-29` - Move model list to config/models.py

### Task 1.6: Add Model Parameter to ContextAnalysisTool
**Changes**:
1. Update `context_analysis_tool.py` execute signature to include `bedrock_model: str`
2. Update orchestrator to pass model to context analysis
3. Remove hardcoded fallback

### Task 1.7: Validate Single Model Usage
**Verification**:
1. Search for any remaining hardcoded model IDs
2. Verify all tools receive model from orchestrator
3. Confirm no tools have default model parameters
4. Test that changing model in config affects all tools

---

## Summary

**Goal**: User selects ONE model → ALL tools use that model

**Changes Required**:
1. ✅ Remove hardcoded defaults in TTCMappingTool
2. ✅ Remove hardcoded fallback in ContextAnalysisTool  
3. ✅ Add model parameter to ContextAnalysisTool
4. ✅ Update orchestrator to pass model to ContextAnalysisTool
5. ✅ Centralize model list for UI selection only
6. ✅ Verify no tool can use a different model than user-selected

**Result**: Single source of truth for model selection throughout application
