# Task 1.1: Audit Hardcoded Model IDs

**Status**: ✅ Complete  
**Date**: October 22, 2025

## Objective

Identify all hardcoded Bedrock model IDs in the codebase.

## Analysis Results

### Hardcoded Model IDs Found (5 locations)

#### 1. src/strands_agent.py:25
```python
bedrock_model: str = "us.anthropic.claude-sonnet-4-20250514-v1:0"
```
**Type**: Default parameter value  
**Usage**: ThreatForestConfig dataclass  
**Impact**: High - affects all orchestrator runs

#### 2. src/modules/tools/setup_tool.py:20-21
```python
"us.anthropic.claude-sonnet-4-20250514-v1:0",
"us.anthropic.claude-opus-4-1-20250805-v1:0",
```
**Type**: Model list  
**Usage**: Available models for selection  
**Impact**: Medium - affects model selection UI

#### 3. src/modules/tools/ttc_mapping_tool.py:30
```python
bedrock_model: str = "us.anthropic.claude-sonnet-4-20250514-v1:0",
```
**Type**: Default parameter value  
**Usage**: TTCMappingTool.execute() method  
**Impact**: Medium - affects TTC mapping step

#### 4. src/modules/tools/context_analysis_tool.py:459
```python
model_id = context_files.get('model_id', 'us.anthropic.claude-sonnet-4-20250514-v1:0')
```
**Type**: Fallback default  
**Usage**: Context analysis fallback  
**Impact**: Low - only used if model_id not provided

## Summary

**Total Hardcoded Models**: 5 locations  
**Unique Models**: 2 (Claude Sonnet 4, Claude Opus 4.1)  
**Files Affected**: 4 files

## Recommendations

1. Create centralized model configuration in `src/config/models.py`
2. Define model categories (fast, balanced, powerful)
3. Add model validation and availability checking
4. Update all files to import from central config

## Next Steps

- Task 1.4: Create centralized configuration
- Task 1.5: Refactor model references
