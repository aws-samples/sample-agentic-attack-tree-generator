# Legacy Core Modules - Archived November 19, 2025

## Overview

These modules were part of the original Strands-based implementation but are **not currently used** in the active codebase. They've been archived here for reference rather than deleted.

---

## Archived Modules (11 files)

### 1. **base_tool.py**
- **Purpose:** Base Tool class and @tool decorator for Strands framework
- **Why Archived:** Tools now use simple class structure without Strands decorators
- **Last Used:** Original Strands implementation

### 2. **bedrock_invoker.py**
- **Purpose:** Centralized Bedrock invocation with async retry logic
- **Why Archived:** Tools use direct boto3 client calls via BedrockClientManager
- **Features:** Automatic retry, throttling handling, error recovery

### 3. **bedrock_service.py**
- **Purpose:** Bedrock service wrapper with rate limiting
- **Why Archived:** Not needed with current synchronous approach
- **Features:** Rate limiter integration, connection pooling

### 4. **error_handler.py**
- **Purpose:** Centralized error handling with recovery strategies
- **Why Archived:** Simple exception handling used instead
- **Features:** Error severity classification, recovery suggestions

### 5. **errors.py**
- **Purpose:** Custom exception classes (ThreatForestError, BedrockError, ValidationError, etc.)
- **Why Archived:** Using standard Python exceptions
- **Features:** Structured error types, context tracking

### 6. **parallel.py**
- **Purpose:** Parallel task execution with concurrency control
- **Why Archived:** Current workflow is fully synchronous
- **Features:** Semaphore-based concurrency, async task management

### 7. **pipeline.py**
- **Purpose:** Pipeline orchestration with dependency management
- **Why Archived:** Direct workflow execution in orchestrator
- **Features:** Stage dependencies, parallel stage execution

### 8. **rate_limiter.py**
- **Purpose:** AWS Bedrock rate limiting and circuit breaker
- **Why Archived:** Tools manage rate limiting individually
- **Features:** Sliding window rate limit, circuit breaker pattern

### 9. **retry.py**
- **Purpose:** Retry decorators with exponential backoff
- **Why Archived:** Simplified error handling approach
- **Features:** Configurable retry strategies, sync/async decorators

### 10. **validation.py**
- **Purpose:** Pydantic input validation models for all tools
- **Why Archived:** Tools validate inputs directly
- **Features:** SetupToolInput, ContextAnalysisInput, ExtractionToolInput, etc.

### 11. **bedrock_invoker.py** (duplicate listing)
- Async invocation wrapper with comprehensive error handling

---

## Still Active (8 modules)

These remain in `src/modules/core/`:

1. ✅ **base_agent.py** - Used by 5 tools for Strands integration
2. ✅ **bedrock_client.py** - BedrockClientManager for connection pooling
3. ✅ **context.py** - Context class for workflow state
4. ✅ **file_discovery.py** - FileDiscovery for project scanning
5. ✅ **progress_emitter.py** - ProgressEmitter for UI updates
6. ✅ **progress_events.py** - ProgressEvent models
7. ✅ **state.py** - ThreatForestState, WorkflowStage
8. ✅ **state_manager.py** - StateManager for checkpointing

---

## Impact Analysis

### No Breaking Changes
- ✅ All archived modules were never used in production code
- ✅ Removal only affects exports in `__init__.py`
- ✅ No tool or workflow depends on these modules

### Code Reduction
- **Before:** 19 core modules
- **After:** 8 core modules
- **Reduction:** 58% of core modules removed
- **Lines Saved:** ~1,500 lines of unused code

---

## Restoration

If you need any archived module:

```bash
# Copy back to core
cp archive_docs/legacy-core/module_name.py src/modules/core/

# Add to __init__.py exports
# from .module_name import ClassName
```

---

## Future Considerations

Some archived modules might be useful for:
- **bedrock_invoker.py** - If moving to async architecture
- **rate_limiter.py** - For high-volume production deployments
- **retry.py** - For more sophisticated error recovery
- **validation.py** - For strict API contracts
- **parallel.py** - For parallel threat processing

Keep these in mind if architecture changes require them.

---

## Archived Date
November 19, 2025

## Archived By
CLI improvements and code cleanup session
