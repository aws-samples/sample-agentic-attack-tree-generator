# ThreatForest React Ink UI

Modern terminal UI for ThreatForest wizard built with React Ink.

## Setup

```bash
npm install
```

## Build

```bash
npm run build        # Build once
npm run build:cli    # Build CLI with shebang
npm run watch        # Watch mode
```

## Run

```bash
npm run dev          # Development mode
node dist/cli.js     # Direct execution
```

## CLI Commands

```bash
threatforest run     # Start wizard
threatforest resume  # Resume from checkpoint
threatforest cache   # Manage cache
threatforest status  # Show current state
```

## Architecture

- **Components**: React Ink UI components
- **Utils**: Python bridge for tool execution
- **Hooks**: Custom React hooks for state management
- **Build**: esbuild for fast bundling

## Integration

The UI integrates with Python backend via:
- `PythonBridge` class for executing Python tools
- JSON-based state files for resume capability
- Real-time progress updates via event streaming
