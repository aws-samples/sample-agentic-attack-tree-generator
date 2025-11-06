# Task 0.4: UI Component Usage Analysis

**Backlog Reference**: [docs/Backlog.md - Task 0.4](../Backlog.md#task-04-analyze-ui-component-usage)

## Component Usage Matrix

### Entry Points:
- ✅ **cli.tsx** - Main CLI entry (imports App, PythonBridge)
- ✅ **index.tsx** - Alternative entry (imports App)

### Components (ui/src/components/)
- ✅ **App.tsx** - Root component (USED)
  - Imports: WelcomeScreen, ConfigurationScreen, ProgressScreen, SummaryScreen, ErrorDisplay, PathSelector, ContinuePrompt
  - Imports hook: useWorkflow
  
- ✅ **WelcomeScreen.tsx** - Mode selection screen (USED by App)
  - Imports: ResumePrompt, ModeSelector
  
- ✅ **ConfigurationScreen.tsx** - AWS/model config (USED by App)
  - Uses: useInput (from ink)
  
- ✅ **ModeSelector.tsx** - Mode selection component (USED by WelcomeScreen)

- ✅ **PathSelector.tsx** - Path selection for enrich/mitigate (USED by App)

- ✅ **ProgressScreen.tsx** - Workflow progress display (USED by App)
  - Imports: StageIndicator, ProgressBar, ProgressDetails, ParallelExecutionDisplay, ETADisplay
  
- ✅ **ProgressDetails.tsx** - Detailed progress info (USED by ProgressScreen)

- ✅ **SummaryScreen.tsx** - Results display (USED by App)

- ✅ **ContinuePrompt.tsx** - Continue to next option (USED by App)
  - Uses: useKeyboard hook

- ✅ **ErrorDisplay.tsx** - Error handling (USED by App)
  - Uses: useKeyboard hook

- ✅ **ResumePrompt.tsx** - Resume workflow prompt (USED by WelcomeScreen)
  - Uses: useKeyboard hook

- ✅ **StageIndicator.tsx** - Stage progress indicator (USED by ProgressScreen)

- ✅ **ProgressBar.tsx** - Progress bar component (USED by ProgressScreen)

- ✅ **ParallelExecutionDisplay.tsx** - Parallel task display (USED by ProgressScreen)

- ✅ **ETADisplay.tsx** - ETA display (USED by ProgressScreen)

- ❌ **ConfigEditor.tsx** - Config editor (NOT USED)
  - Uses: useKeyboard hook
  - No imports found

- ❌ **ThreatSelector.tsx** - Threat selection (NOT USED)
  - Uses: useKeyboard hook
  - No imports found

- ❌ **FileDiscoveryDisplay.tsx** - File discovery display (NOT USED)
  - No imports found

### Hooks (ui/src/hooks/)
- ✅ **useWorkflow.ts** - Workflow state management (USED by App)
  - Imports: WorkflowExecutor from utils

- ✅ **useInput.ts** - Keyboard input hook (USED by 5 components)
  - Exports: useKeyboard
  - Used by: ErrorDisplay, ConfigEditor, ResumePrompt, ContinuePrompt, ThreatSelector

### Utils (ui/src/utils/)
- ✅ **pythonBridge.ts** - Python communication (USED by cli.tsx, WorkflowExecutor, App)

- ✅ **workflowExecutor.ts** - Workflow orchestration (USED by useWorkflow)
  - Imports: PythonBridge

## Component Tree

```
cli.tsx (ENTRY POINT)
└── App.tsx
    ├── WelcomeScreen.tsx
    │   ├── ResumePrompt.tsx ✅
    │   │   └── useKeyboard (useInput.ts) ✅
    │   └── ModeSelector.tsx ✅
    ├── ConfigurationScreen.tsx ✅
    │   └── useInput (from ink) ✅
    ├── PathSelector.tsx ✅
    ├── ProgressScreen.tsx ✅
    │   ├── StageIndicator.tsx ✅
    │   ├── ProgressBar.tsx ✅
    │   ├── ProgressDetails.tsx ✅
    │   ├── ParallelExecutionDisplay.tsx ✅
    │   └── ETADisplay.tsx ✅
    ├── SummaryScreen.tsx ✅
    ├── ContinuePrompt.tsx ✅
    │   └── useKeyboard (useInput.ts) ✅
    ├── ErrorDisplay.tsx ✅
    │   └── useKeyboard (useInput.ts) ✅
    └── useWorkflow.ts ✅
        └── WorkflowExecutor (workflowExecutor.ts) ✅
            └── PythonBridge (pythonBridge.ts) ✅

UNUSED COMPONENTS:
├── ConfigEditor.tsx ❌
│   └── useKeyboard (useInput.ts) ✅
├── ThreatSelector.tsx ❌
│   └── useKeyboard (useInput.ts) ✅
└── FileDiscoveryDisplay.tsx ❌
```

## Summary Statistics

### Total Files: 23
- Entry points: 2
- Components: 18
- Hooks: 2
- Utils: 2

### USED: 20/23 (87%)
- ✅ Entry points: 2/2
- ✅ Components: 15/18
- ✅ Hooks: 2/2
- ✅ Utils: 2/2

### UNUSED: 3/23 (13%)
- ❌ Components: 3/18
  1. ConfigEditor.tsx
  2. ThreatSelector.tsx
  3. FileDiscoveryDisplay.tsx

## Removal Candidates

### High Confidence - Unused Components (3):

1. **ui/src/components/ConfigEditor.tsx**
   - Purpose: Config file editor
   - No imports found in any file
   - Uses useKeyboard hook (which IS used elsewhere)
   - **Reason**: Not part of current UI flow

2. **ui/src/components/ThreatSelector.tsx**
   - Purpose: Threat selection interface
   - No imports found in any file
   - Uses useKeyboard hook (which IS used elsewhere)
   - **Reason**: Not part of current UI flow

3. **ui/src/components/FileDiscoveryDisplay.tsx**
   - Purpose: Display file discovery results
   - No imports found in any file
   - **Reason**: Not part of current UI flow

### Notes:
- All 3 unused components appear to be from an older UI design
- useKeyboard hook (useInput.ts) IS used by other components, so keep it
- No orphaned hooks or utilities found

## Component Flow Analysis

### Option 1 (Full Workflow):
```
WelcomeScreen → ConfigurationScreen → ProgressScreen → ContinuePrompt → SummaryScreen
```

### Option 2 (Enrich):
```
WelcomeScreen → PathSelector → ProgressScreen → SummaryScreen
```

### Option 3 (Mitigate):
```
WelcomeScreen → PathSelector → ProgressScreen → SummaryScreen
```

### Error Handling:
```
Any screen → ErrorDisplay (on error)
```

### Resume Flow:
```
WelcomeScreen → ResumePrompt (if state exists) → ConfigurationScreen
```

## Deliverables
- ✅ Component usage tree (complete with all 23 files)
- ✅ List of unused components (3 components)
- ✅ List of unused utilities (none - all used)
- ✅ Component flow diagrams for all 3 modes

## Recommendations

### Immediate Removal (High Confidence):
1. Remove `ui/src/components/ConfigEditor.tsx`
2. Remove `ui/src/components/ThreatSelector.tsx`
3. Remove `ui/src/components/FileDiscoveryDisplay.tsx`

### Keep All:
- All hooks (useWorkflow.ts, useInput.ts) - actively used
- All utilities (pythonBridge.ts, workflowExecutor.ts) - actively used
- All other 15 components - part of active UI flow

### Impact:
- No breaking changes (unused components not imported)
- Clean up old/deprecated UI components
- Reduce maintenance burden
