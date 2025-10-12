# UI Workflow Sequential Execution Fix

## Issue
The React UI was simulating workflow execution with `setTimeout` instead of actually calling the Python backend sequentially. This caused the workflow to appear to run but not actually execute the threat analysis.

## Root Cause
The `WorkflowExecutor` class in `ui/src/utils/workflowExecutor.ts` was using placeholder code with simulated parallel execution:

```typescript
// OLD CODE - Simulated execution
await new Promise(resolve => setTimeout(resolve, 2000));
```

This was never replaced with actual Python backend calls, so the UI would show progress but no real analysis was performed.

## Solution

### 1. Updated WorkflowExecutor
Modified `ui/src/utils/workflowExecutor.ts` to call Python backend sequentially:

```typescript
async executeWorkflow() {
  // Stage 1: Setup & Context Analysis
  const contextResult = await this.bridge.runContextAnalysis(this.config.projectPath);
  
  // Stage 2: Information Extraction
  const extractionResult = await this.bridge.runInformationExtraction({...});
  
  // Stage 3: Attack Tree Generation
  const treesResult = await this.bridge.runAttackTreeGeneration({...});
  
  // Stage 4: Summary Generation
  const summaryResult = await this.bridge.runSummaryGeneration({...});
}
```

### 2. Added Python Bridge Methods
Added four new methods to `ui/src/utils/pythonBridge.ts`:

- `runContextAnalysis(projectPath)` - Calls `ContextAnalysisTool.execute()`
- `runInformationExtraction(params)` - Calls `InformationExtractionTool.execute()`
- `runAttackTreeGeneration(params)` - Calls `AttackTreeGeneratorTool.execute()`
- `runSummaryGeneration(params)` - Calls `SummaryGeneratorTool.execute()`

Each method:
- Spawns a Python process with proper async/await handling
- Passes parameters as JSON
- Captures stdout/stderr
- Returns structured `PythonResult` with success/error status

## Execution Flow

### Sequential Workflow
```
UI Setup Screen
    ↓
WorkflowExecutor.executeWorkflow()
    ↓
1. Context Analysis (await)
    ↓
2. Information Extraction (await)
    ↓
3. Attack Tree Generation (await)
    ↓
4. Summary Generation (await)
    ↓
Complete Screen
```

### Key Points
- Each stage **waits** for the previous stage to complete
- No parallel execution - fully sequential
- Matches the Python wizard's execution pattern
- Progress updates happen between stages
- Errors propagate properly and stop execution

## Verification

### Before Fix
- UI showed progress bars
- Completed in ~5 seconds
- No output files generated
- No actual AI analysis performed

### After Fix
- UI shows real progress
- Takes actual time (minutes depending on threats)
- Generates attack trees and reports
- Full AI analysis with Bedrock

## Testing

To test the fix:

```bash
cd /Users/dicorteg/Documents/ThreatForest/ThreatForest-internal/kiro-threatforest-agentic/threatforest-strands
./threatforest.py run
```

Expected behavior:
1. Welcome screen appears
2. Configuration screen collects inputs
3. Progress screen shows real-time updates
4. Each stage takes actual time to complete
5. Output files are generated in `threatforest_output/`
6. Summary screen shows results

## Files Modified

1. `ui/src/utils/workflowExecutor.ts` - Fixed sequential execution
2. `ui/src/utils/pythonBridge.ts` - Added workflow execution methods
3. `ui/dist/cli.js` - Rebuilt with fixes

## Impact Analysis

### Affected Components
- ✅ WorkflowExecutor - Now calls real Python backend
- ✅ PythonBridge - Added 4 new workflow methods
- ✅ ProgressScreen - Now shows real progress
- ✅ SummaryScreen - Now displays actual results
- ✅ Error handling - Properly propagates Python errors

### Not Affected
- ConfigurationScreen - No changes needed
- WelcomeScreen - No changes needed
- State management - Works as designed
- Cache functionality - Independent of workflow

## Future Improvements

1. **Progress Streaming**: Stream real-time progress from Python instead of stage-level updates
2. **Cancellation**: Add ability to cancel running workflow
3. **Resume**: Implement checkpoint-based resume functionality
4. **Parallel Trees**: Optionally generate attack trees in parallel (with proper orchestration)

## Conclusion

The UI now properly executes the ThreatForest workflow sequentially, matching the Python wizard's behavior. Each stage waits for completion before proceeding, ensuring proper data flow and error handling.
