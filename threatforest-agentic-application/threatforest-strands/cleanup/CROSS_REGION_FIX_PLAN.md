# Cross-Region Inference Fix Plan

## Problem Summary
Application is attempting to invoke Bedrock models in **us-east-2** when it should use **us-east-1**, causing AccessDeniedException due to SCP blocking us-east-2.

### Error Pattern
```
AccessDeniedException: User is not authorized to perform: bedrock:InvokeModel 
on resource: arn:aws:bedrock:us-east-2::foundation-model/anthropic.claude-sonnet-4-20250514-v1:0
```

## Root Causes

### 1. Cross-Region Inference Profile Usage
- Model IDs starting with `us.` (e.g., `us.anthropic.claude-sonnet-4-20250514-v1:0`)
- These are converted to ARNs with hardcoded `us-east-1` region
- But the Bedrock client is created with wrong region

### 2. Inconsistent Default Regions
- `bedrock_client.py`: defaults to `us-west-2`
- `bedrock_service.py`: defaults to `us-west-2`
- ARN conversion: hardcoded to `us-east-1`
- Actual invocation: resolves to `us-east-2` (likely from AWS config)

### 3. Files with Cross-Region Logic
```
src/modules/core/bedrock_invoker.py:108-109
src/modules/tools/information_extraction_tool.py:127-128
src/modules/tools/context_analysis_tool.py (if exists)
```

## Recommended Solution: Remove Cross-Region Inference

### Why This Approach?
1. **Simpler**: No ARN conversion needed
2. **More predictable**: Direct model invocation
3. **Region agnostic**: Works with any region
4. **Avoids SCP issues**: No cross-region calls

### Implementation Steps

#### Step 1: Update Model Definitions
**File**: `src/wizard.py` (lines 403-426)

Replace cross-region models with regional equivalents:

```python
def _get_fallback_models(self) -> List[Dict[str, str]]:
    """Fallback model list if API call fails"""
    return [
        {
            'name': 'Claude Sonnet 4',
            'id': 'anthropic.claude-sonnet-4-20250514-v1:0',  # Changed from us.anthropic
            'recommendation': '⭐ Recommended - Best balance of speed and accuracy'
        },
        {
            'name': 'Claude Opus 4.1',
            'id': 'anthropic.claude-opus-4-1-20250805-v1:0',  # Changed from us.anthropic
            'recommendation': '🚀 Most powerful - Highest accuracy, slower'
        },
        {
            'name': 'Claude 3.5 Sonnet',
            'id': 'anthropic.claude-3-5-sonnet-20241022-v2:0',
            'recommendation': '⚡ Fast - Good for quick analysis'
        },
        {
            'name': 'Claude 3 Haiku',
            'id': 'anthropic.claude-3-haiku-20240307-v1:0',
            'recommendation': '💨 Fastest - Basic analysis'
        }
    ]
```

#### Step 2: Remove ARN Conversion Logic
**File**: `src/modules/core/bedrock_invoker.py` (lines 107-109)

```python
# REMOVE these lines:
# if model_id.startswith('us.') or model_id.startswith('eu.'):
#     model_id = f"arn:aws:bedrock:us-east-1::foundation-model/{model_id}"

# Keep direct model_id usage
response = bedrock.invoke_model(
    modelId=model_id,  # Use model_id directly
    body=json.dumps(body)
)
```

**File**: `src/modules/tools/information_extraction_tool.py` (lines 126-128)

```python
# REMOVE these lines:
# if model_id.startswith('us.') or model_id.startswith('eu.'):
#     model_id = f"arn:aws:bedrock:us-east-1::foundation-model/{model_id}"
```

#### Step 3: Fix Default Regions
**File**: `src/modules/core/bedrock_client.py` (line 26)

```python
def get_client(
    self,
    profile_name: Optional[str] = None,
    region_name: str = "us-east-1"  # Changed from us-west-2
):
```

**File**: `src/modules/core/bedrock_service.py` (line 14)

```python
def __init__(
    self,
    profile_name: Optional[str] = None,
    region_name: str = "us-east-1"  # Changed from us-west-2
):
```

#### Step 4: Update Model Priority Logic
**File**: `src/wizard.py` (lines 364-365)

```python
# REMOVE cross-region preference:
# priority = 0 if model_id.startswith('us.') else 10

# Replace with version-based priority only:
priority = 0  # All models equal priority, sort by version/date
```

#### Step 5: Update Documentation
**Files to update**:
- `README.md` - Update model IDs in examples
- `docs/OVERVIEW.md` - Update recommended models section
- `docs/PRIORITY_2_BEDROCK_INVOCATION.md` - Update ARN conversion notes

### Alternative Solution: Fix Region Consistency

If you must use cross-region inference profiles:

#### Step 1: Fix Default Regions (same as above)

#### Step 2: Ensure Region Propagation
**File**: `src/modules/core/bedrock_invoker.py`

```python
def invoke_model_sync(
    bedrock,
    model_id: str,
    prompt: str,
    system_prompt: Optional[str] = None,
    temperature: float = 0.7,
    region_name: str = "us-east-1"  # Add region parameter
) -> str:
    # Convert cross-region inference profile IDs to ARNs with correct region
    if model_id.startswith('us.') or model_id.startswith('eu.'):
        model_id = f"arn:aws:bedrock:{region_name}::foundation-model/{model_id}"
```

#### Step 3: Pass Region Through Call Chain
Ensure all tools pass `region_name` parameter through to `bedrock_invoker`.

## Testing Plan

### Test 1: Verify Model Selection
```bash
python src/wizard.py
# Select model and verify it shows anthropic.* not us.anthropic.*
```

### Test 2: Run Full Analysis
```bash
python threatforest.py \
  --project examples/hcls-example \
  --bedrock-model anthropic.claude-sonnet-4-20250514-v1:0
```

### Test 3: Check Logs
```bash
# Verify no us-east-2 references
grep -r "us-east-2" output/logs/
# Should return no results

# Verify us-east-1 usage
grep -r "us-east-1" output/logs/
```

## Additional Issues Found

### Issue 1: Model Availability
Cross-region inference profiles may not be available in all accounts. Regional models are more widely available.

### Issue 2: Pricing
Cross-region inference may have different pricing. Regional models have standard pricing.

### Issue 3: Latency
Cross-region inference adds routing overhead. Regional models have lower latency.

## Rollback Plan

If issues occur after changes:

1. Revert model definitions in `wizard.py`
2. Restore ARN conversion in `bedrock_invoker.py`
3. Keep region fixes (us-east-1 defaults)

## Success Criteria

- [ ] No AccessDeniedException errors
- [ ] All Bedrock calls use us-east-1
- [ ] No references to us-east-2 in logs
- [ ] Attack trees generate successfully
- [ ] All 4 high-priority threats processed

## Timeline

- **Step 1-2**: 15 minutes (model definitions + ARN removal)
- **Step 3**: 5 minutes (region defaults)
- **Step 4**: 5 minutes (priority logic)
- **Step 5**: 10 minutes (documentation)
- **Testing**: 15 minutes

**Total**: ~50 minutes
