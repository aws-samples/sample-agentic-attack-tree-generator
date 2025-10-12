# React UI to Python Handoff Verification

## Overview
This document verifies the complete data flow from the React UI to Python backend, ensuring proper Pydantic v2 compatibility and correct method invocations.

## Architecture

### Flow Diagram
```
React UI (TypeScript)
    ↓
PythonBridge (TypeScript)
    ↓
spawn Python process
    ↓
Python Modules (Pydantic v2)
    ↓
JSON Response
    ↓
React UI
```

## Key Components

### 1. React UI Entry Point
**File**: `ui/src/cli.tsx`
- Handles CLI commands: `run`, `resume`, `cache`, `status`, `help`
- Renders React components using Ink
- Delegates Python operations to PythonBridge

### 2. Configuration Screen
**File**: `ui/src/components/ConfigurationScreen.tsx`
- Collects user inputs:
  - Project path
  - AWS profile
  - Bedrock model (10 models available)
- Passes configuration to workflow via `onNext()` callback

### 3. Python Bridge
**File**: `ui/src/utils/pythonBridge.ts`

#### Key Methods:

##### `discoverFiles(projectPath: string)`
- **Python Module**: `src.modules.core.file_discovery.FileDiscovery`
- **Method**: Static method `discover(project_path)`
- **Returns**: `DiscoveredFiles` dataclass
- **Serialization**: Converts dataclass to dict for JSON

##### `getCacheStats()`
- **Python Module**: `src.modules.core.cache.BedrockResponseCache`
- **Method**: Instance method `get_stats()`
- **Returns**: Dict with cache statistics

##### `clearCache()`
- **Python Module**: `src.modules.core.cache.BedrockResponseCache`
- **Method**: Instance method `clear()`
- **Returns**: Success message

##### `loadState()`
- **Python Module**: `src.modules.core.state_manager.StateManager`
- **Method**: Instance method `load_checkpoint('latest')`
- **Returns**: `ThreatForestState` (Pydantic v2 model)
- **Serialization**: Uses `model_dump()` (Pydantic v2 API)

##### `saveState(state: any)`
- **Python Module**: `src.modules.core.state_manager.StateManager`
- **Method**: Instance method `save_checkpoint(state, 'latest')`
- **Input**: Creates `ThreatForestState` instance (validates during `__init__`)
- **Returns**: Success message

##### `validateInput(inputType: string, data: any)`
- **Python Module**: `src.modules.core.validation`
- **Classes**: `SetupToolInput`, `ContextAnalysisInput`, `ExtractionToolInput`, `AttackTreeGeneratorInput`
- **Validation**: Pydantic v2 validates during `__init__`
- **Serialization**: Uses `model_dump()` (Pydantic v2 API)

## Pydantic v2 Compatibility

### Key Changes from v1 to v2

1. **Validation**
   - ✗ v1: `Model.validate(data)` - REMOVED
   - ✓ v2: `Model(**data)` - Validates during instantiation

2. **Serialization**
   - ✗ v1: `instance.dict()` - REMOVED
   - ✓ v2: `instance.model_dump()` - New method

3. **Field Validators**
   - ✓ v2: `@field_validator('field_name')` with `@classmethod`
   - ✓ v2: `@model_validator(mode='after')` for cross-field validation

### Implementation in Python Bridge

All Python bridge methods correctly use Pydantic v2 API:

```python
# Validation (happens during __init__)
instance = SetupToolInput(**data)

# Serialization
data = instance.model_dump()
```

## Data Flow Examples

### Example 1: File Discovery
```typescript
// React UI
const result = await bridge.discoverFiles('/path/to/project');

// Python execution
FileDiscovery.discover('/path/to/project')
  → Returns DiscoveredFiles dataclass
  → Converts to dict
  → JSON serialization

// React receives
{
  success: true,
  data: {
    threat_models: [...],
    source_code: [...],
    total_files: 228,
    discovery_time_ms: 14.95
  }
}
```

### Example 2: Input Validation
```typescript
// React UI
const result = await bridge.validateInput('setup', {
  project_path: '/path/to/project',
  bedrock_model: 'anthropic.claude-3-5-sonnet-20241022-v2:0'
});

// Python execution
SetupToolInput(**data)  # Validates during __init__
  → If valid: Returns model_dump()
  → If invalid: Raises ValidationError

// React receives (success)
{
  success: true,
  data: {
    project_path: '/path/to/project',
    bedrock_model: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
    aws_profile: null,
    interactive: true
  }
}

// React receives (failure)
{
  success: false,
  error: 'Project path does not exist: /invalid/path',
  traceback: '...'
}
```

### Example 3: State Management
```typescript
// React UI - Save state
const state = {
  project_path: '/path/to/project',
  bedrock_model: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
  current_stage: 'setup',
  setup_complete: true
};
await bridge.saveState(state);

// Python execution
ThreatForestState(**state_data)  # Validates during __init__
manager.save_checkpoint(state, 'latest')

// React UI - Load state
const result = await bridge.loadState();

// Python execution
state = manager.load_checkpoint('latest')
data = state.model_dump()  # Pydantic v2 API

// React receives
{
  success: true,
  data: {
    current_stage: 'setup',
    project_path: '/path/to/project',
    bedrock_model: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
    setup_complete: true,
    ...
  }
}
```

## Testing

### Test Script
**File**: `test_python_bridge.py`

Tests all critical components:
1. ✓ FileDiscovery static method
2. ✓ BedrockResponseCache instantiation and methods
3. ✓ StateManager with Pydantic v2 models
4. ✓ Validation models with Pydantic v2 API

### Test Results
```
FileDiscovery        ✓ PASS
Cache                ✓ PASS
StateManager         ✓ PASS
Validation           ✓ PASS
```

## Error Handling

### Python Errors
All Python bridge methods wrap execution in try-except:
```python
try:
    # Execute Python code
    result = ...
    print(json.dumps({'success': True, 'data': result}))
except Exception as e:
    import traceback
    print(json.dumps({
        'success': False,
        'error': str(e),
        'traceback': traceback.format_exc()
    }))
```

### TypeScript Error Handling
```typescript
python.on('close', (code) => {
  if (code !== 0) {
    resolve({ success: false, error: error || 'Python process failed' });
  } else {
    try {
      const result = JSON.parse(output);
      resolve(result);
    } catch (e) {
      resolve({ success: false, error: 'Failed to parse Python output' });
    }
  }
});
```

## Configuration

### Environment Variables
- `PYTHON_PATH`: Path to Python interpreter (defaults to `python`)
- `NODE_ENV`: Set to `production` by `threatforest.py`

### Project Root Calculation
```typescript
// Since CLI runs from ui/ directory
this.projectRoot = path.join(process.cwd(), '..');
```

### Python Path Setup
```python
sys.path.insert(0, '${this.projectRoot}')
```

## Available Bedrock Models

The UI presents 10 Bedrock models:
1. Claude Sonnet 4 (`us.anthropic.claude-sonnet-4-20250514-v1:0`)
2. Claude Opus 4.1 (`us.anthropic.claude-opus-4-1-20250805-v1:0`)
3. Claude 3.5 Sonnet (`anthropic.claude-3-5-sonnet-20241022-v2:0`)
4. Claude 3.5 Haiku (`anthropic.claude-3-5-haiku-20241022-v1:0`)
5. Claude 3 Opus (`anthropic.claude-3-opus-20240229-v1:0`)
6. Claude 3 Haiku (`anthropic.claude-3-haiku-20240307-v1:0`)
7. Titan Text Premier (`amazon.titan-text-premier-v1:0`)
8. Titan Text Express (`amazon.titan-text-express-v1`)
9. Llama 3.2 90B (`meta.llama3-2-90b-instruct-v1:0`)
10. Llama 3.2 11B (`meta.llama3-2-11b-instruct-v1:0`)

## Validation Models

### SetupToolInput
- `project_path`: Required, must exist and be a directory
- `aws_profile`: Optional
- `bedrock_model`: Optional
- `inference_profile_arn`: Optional
- `interactive`: Boolean, default True

### ContextAnalysisInput
- `project_path`: Required, must exist and be a directory

### ExtractionToolInput
- `context_files`: Required, non-empty dict
- `bedrock_model`: Required, non-empty string
- `aws_profile`: Optional
- `interactive`: Boolean, default False

### AttackTreeGeneratorInput
- `threat_statements`: Required, non-empty list
- `extracted_info`: Required, dict
- `bedrock_model`: Required, non-empty string
- `aws_profile`: Optional

## Workflow State

### WorkflowStage Enum
- `SETUP`
- `CONTEXT_ANALYSIS`
- `EXTRACTION`
- `TREE_GENERATION`
- `MAPPING`
- `SUMMARY`
- `COMPLETE`

### ThreatForestState Fields
- Workflow metadata: `current_stage`, `started_at`, `last_updated`
- Configuration: `project_path`, `aws_profile`, `bedrock_model`
- Completion flags: `setup_complete`, `context_complete`, etc.
- Stage results: `setup_result`, `context_files`, `extracted_info`, etc.
- Error tracking: `errors` list

## Verification Checklist

- [x] FileDiscovery uses static method correctly
- [x] Cache methods instantiate BedrockResponseCache
- [x] StateManager uses Pydantic v2 `model_dump()`
- [x] Validation uses Pydantic v2 instantiation pattern
- [x] All methods handle errors properly
- [x] JSON serialization works for all data types
- [x] Virtual environment is used for Python execution
- [x] Project root path is calculated correctly
- [x] All 10 Bedrock models are available in UI
- [x] Test script validates all components

## Conclusion

The React UI to Python handoff is fully compatible with Pydantic v2. All methods correctly:
1. Instantiate Python classes
2. Call appropriate methods (static vs instance)
3. Use Pydantic v2 API (`model_dump()` instead of `dict()`)
4. Validate inputs during instantiation
5. Handle errors and serialize responses
6. Execute in the correct virtual environment

The system is ready for production use.
