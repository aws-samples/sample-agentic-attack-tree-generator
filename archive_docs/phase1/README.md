# Phase 1: Bedrock Model Configuration Centralization

**Status**: 🔄 In Progress  
**Start Date**: October 22, 2025

## Overview

Phase 1 focuses on ensuring the user-selected Bedrock model during initial configuration is the ONLY model used throughout the entire application. This eliminates hardcoded model defaults and ensures consistent model usage across all tools.

## Goal

**Single Model Selection**: User selects ONE model → ALL tools use that model (no exceptions)

## Task Documents

- ✅ [Task 1.1: Audit Hardcoded Model IDs](task_1.1_model_audit.md)
- ✅ [Task 1.2: Audit Hardcoded Regions](task_1.2_region_audit.md)
- ✅ [Task 1.3: Audit Inline Prompts](task_1.3_prompt_audit.md)
- 📋 [Task 1.4: Implementation Plan](task_1.4_implementation_plan.md)
- 📋 [Bedrock Model Flow Analysis](bedrock_model_flow.md)

## Implementation Summary

### Changes Required (5 files)

1. **NEW**: `src/config/models.py` - Centralized model list
2. **MODIFY**: `src/modules/tools/ttc_mapping_tool.py` - Remove default parameter
3. **MODIFY**: `src/modules/tools/context_analysis_tool.py` - Add model parameter, remove fallback
4. **MODIFY**: `src/strands_agent.py` - Pass model to context analysis, use centralized default
5. **MODIFY**: `src/modules/tools/setup_tool.py` - Use centralized model list

### Key Changes

**Remove Hardcoded Defaults**:
- TTCMappingTool: Remove `bedrock_model = "us.anthropic.claude-sonnet-4-20250514-v1:0"` default
- ContextAnalysisTool: Remove hardcoded fallback model

**Add Missing Parameter**:
- ContextAnalysisTool: Add `bedrock_model: str` parameter to execute()
- Orchestrator: Pass model to context analysis tool

**Centralize Configuration**:
- Create ModelConfig class with AVAILABLE_MODELS list
- All components import from single source

## Success Criteria

- ✅ User selects ONE model during setup
- ✅ ALL tools use that selected model
- ✅ No hardcoded model defaults in tools
- ✅ No hardcoded model fallbacks
- ✅ Centralized model list for UI
- ✅ All tests passing

## Backlog Reference

[docs/Backlog.md - Phase 1](../Backlog.md#phase-1-bedrock-model-configuration-centralization)
