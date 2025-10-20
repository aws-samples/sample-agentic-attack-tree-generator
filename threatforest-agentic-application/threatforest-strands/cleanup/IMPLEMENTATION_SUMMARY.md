# Cross-Region Inference Fix - Implementation Summary

## Changes Completed ✅

### 1. Model Definitions Updated
**File**: `src/wizard.py`
- Replaced `us.anthropic.claude-sonnet-4-20250514-v1:0` → `anthropic.claude-sonnet-4-20250514-v1:0`
- Replaced `us.anthropic.claude-opus-4-1-20250805-v1:0` → `anthropic.claude-opus-4-1-20250805-v1:0`
- Removed cross-region model priority preference
- **CRITICAL**: Disabled inference profile ARN mapping (line 264) - now uses direct model IDs

### 2. ARN Conversion Removed
**File**: `src/modules/core/bedrock_invoker.py`
- Removed lines that converted `us.` and `eu.` prefixed model IDs to ARNs
- Models now invoked directly with their model ID

**File**: `src/modules/tools/information_extraction_tool.py`
- Removed ARN conversion logic from `_bedrock_call_with_retry` method

**File**: `src/modules/tools/context_analysis_tool.py`
- Fixed hardcoded model ID from `us.anthropic.*` to `anthropic.*`

### 3. Default Regions Fixed
**File**: `src/modules/core/bedrock_client.py`
- Changed default region: `us-west-2` → `us-east-1`

**File**: `src/modules/core/bedrock_service.py`
- Changed default region: `us-west-2` → `us-east-1`

### 4. Documentation Updated
**File**: `docs/OVERVIEW.md`
- Updated recommended model IDs to use regional format

## Root Cause Analysis

The issue had **two layers**:

1. **Cross-region inference profile models** (`us.anthropic.*`) - Fixed by updating fallback models
2. **Automatic inference profile mapping** - The wizard was fetching inference profiles from Bedrock API and automatically mapping regional model IDs to inference profile ARNs, which caused cross-region routing

## What This Fixes

### Before
```
Error 1: AccessDeniedException on resource: 
arn:aws:bedrock:us-east-2::foundation-model/anthropic.claude-sonnet-4-20250514-v1:0

Error 2: AccessDeniedException on resource:
arn:aws:bedrock:::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0
(malformed ARN from inference profile)
```

### After
- All Bedrock calls use `us-east-1` region
- No inference profile ARN mapping
- Direct model invocation with model IDs
- Simpler, more predictable behavior

## Testing

Run the application to verify:

```bash
source venv/bin/activate
python threatforest.py --project examples/hcls-example
```

Expected results:
- ✅ No AccessDeniedException errors
- ✅ No references to us-east-2 in logs
- ✅ No inference profile ARNs in logs
- ✅ Attack trees generate successfully
- ✅ All Bedrock calls complete

## Verification Commands

```bash
# Check for any remaining us-east-2 references
grep -r "us-east-2" output/logs/

# Check for inference profile ARNs
grep -r "inference-profile" output/logs/

# Verify direct model ID usage
grep -r "anthropic.claude" output/logs/ | grep -v "us.anthropic"
```

## Files Modified

1. `src/wizard.py` - Model definitions, priority logic, **inference profile mapping disabled**
2. `src/modules/core/bedrock_invoker.py` - Removed ARN conversion
3. `src/modules/tools/information_extraction_tool.py` - Removed ARN conversion
4. `src/modules/tools/context_analysis_tool.py` - Fixed hardcoded model ID
5. `src/modules/core/bedrock_client.py` - Fixed default region
6. `src/modules/core/bedrock_service.py` - Fixed default region
7. `docs/OVERVIEW.md` - Updated documentation

## Benefits

1. **Simpler**: No ARN conversion or inference profile mapping
2. **More reliable**: Direct model invocation
3. **Region agnostic**: Works with any region (just change default)
4. **SCP compliant**: No cross-region calls
5. **Better performance**: No routing overhead
6. **Predictable**: Model ID you select is the model ID used
