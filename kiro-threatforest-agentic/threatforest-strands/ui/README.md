# ThreatForest React Ink UI

Modern terminal UI for ThreatForest wizard built with React Ink.

## Installation

```bash
cd ui
npm install
npm run build:all
npm link  # Install globally
```

## CLI Commands

### Start New Session
```bash
threatforest run
# or simply
threatforest
```

### Resume from Checkpoint
```bash
threatforest resume
```

### Manage Cache
```bash
threatforest cache stats   # Show cache statistics
threatforest cache clear   # Clear all cached responses
threatforest cache info    # Show cache configuration
```

### Check Status
```bash
threatforest status
```

### Help
```bash
threatforest help
```

## Development

```bash
npm install              # Install dependencies
npm run build:all        # Build both index and CLI
npm run dev              # Development mode
npm run watch            # Watch mode
```

## Architecture

- **Components**: React Ink UI components
  - App - Main application with screen routing
  - WelcomeScreen - Logo and resume detection
  - ConfigurationScreen - Project/AWS/Model config
  - ProgressScreen - Stage-based progress with ETA
  - SummaryScreen - Final results and metrics
  - ErrorDisplay - Error handling with recovery
  - ResumePrompt - Interactive resume/restart
  - ThreatSelector - Multi-select threat filtering
  - ParallelExecutionDisplay - Parallel task visualization
  - ETADisplay - Real-time ETA and elapsed time

- **Utils**: Python bridge for tool execution
  - PythonBridge - Execute Python tools
  - WorkflowExecutor - Orchestrate workflow stages

- **Hooks**: Custom React hooks
  - useWorkflow - Workflow state management
  - useKeyboard - Keyboard input handling

- **Build**: esbuild for fast bundling

## Integration

The UI integrates with Python backend via:
- `PythonBridge` class for executing Python tools
- JSON-based state files for resume capability
- Real-time progress updates via callbacks
- Cache integration for statistics display

## Features

✅ Modern, interactive terminal UI  
✅ Real-time progress with ETA  
✅ Resume from checkpoint  
✅ Cache statistics display  
✅ Error handling with recovery  
✅ Parallel execution visualization  
✅ Keyboard navigation  
✅ Stage-based workflow  

## Requirements

- Node.js 18+
- Python 3.8+
- ThreatForest Python backend
