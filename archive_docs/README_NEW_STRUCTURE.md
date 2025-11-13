# ThreatForest - Setup & Usage Guide

## Quick Start

### One-Command Setup

```bash
./setup.sh
```

This will:
1. Install Python dependencies
2. Install Node.js dependencies
3. Build the React UI

Then run:
```bash
python threatforest.py
```

### Manual Setup

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Build React UI
cd ui
npm install
npm run build:cli
cd ..

# 3. Run ThreatForest
python threatforest.py
```

## Requirements

- **Python**: 3.8+
- **Node.js**: 16+ (for React Ink UI)
- **npm**: Comes with Node.js

## Installation

### 1. Clone Repository

```bash
git clone <repository-url>
cd threatforest-strands
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

Or install in development mode:

```bash
pip install -e .
```

### 3. Run ThreatForest

```bash
python threatforest.py
```

The UI will build automatically on first run.

## Usage

### Start New Analysis

```bash
python threatforest.py
# or
python threatforest.py run
```

### Resume from Checkpoint

```bash
python threatforest.py resume
```

### Cache Management

```bash
python threatforest.py cache stats    # View cache statistics
python threatforest.py cache info     # View cache configuration
python threatforest.py cache clear    # Clear cache
```

### Check Workflow Status

```bash
python threatforest.py status
```

## Folder Structure

```
threatforest-strands/
├── threatforest.py              # Main entry point - run this!
├── setup.py                     # Package installation
├── src/                         # All source code
│   ├── modules/
│   │   ├── core/               # Core functionality
│   │   ├── parsers/            # Threat parsers
│   │   ├── tools/              # Strands tools
│   │   ├── cli/                # CLI utilities
│   │   └── utils/              # Utilities
│   ├── strands_agent.py        # Main orchestrator
│   └── wizard.py               # Interactive wizard
├── tests/                       # All tests organized by group
│   ├── validation-parsing/
│   ├── performance-optimization/
│   └── infrastructure-reliability/
├── output/                      # All output files
│   ├── attack_trees/           # Generated attack trees
│   ├── logs/                   # Application logs
│   └── state/                  # State checkpoints
└── ui/                         # React Ink UI

```

## Output Files

All generated files are organized in the `output/` directory:

- **Attack Trees**: `output/attack_trees/*.md` - Generated attack tree files
- **Logs**: `output/logs/threatforest.log` - Application logs with rotation
- **State**: `output/state/workflow_state.json` - Workflow checkpoints for resume

## Development

### Run Tests

```bash
python -m pytest tests/ -v
```

### Run Specific Test Group

```bash
python -m pytest tests/validation-parsing/ -v
python -m pytest tests/performance-optimization/ -v
python -m pytest tests/infrastructure-reliability/ -v
```

### Development Mode (UI)

For UI development with hot reload:

```bash
cd ui
npm run watch
```

## Troubleshooting

### UI Build Fails

If automatic build fails, try manual build:

```bash
cd ui
rm -rf node_modules dist
npm install
npm run build:cli
cd ..
python threatforest.py
```

### Node.js Not Found

Install Node.js from https://nodejs.org/ (version 16 or higher)

### Python Dependencies Missing

```bash
pip install -r requirements.txt
```

## Architecture

### Entry Point Flow

```
python threatforest.py
    ↓
Checks: ui/dist/cli.js exists?
    ↓ No
Auto-build: npm install && npm run build:cli
    ↓ Yes
Launch: node ui/dist/cli.js [args]
    ↓
React Ink UI (TypeScript)
    ↓
Python Bridge (JSON IPC)
    ↓
Python Tools (src/modules/)
```

### Key Components

- **threatforest.py** - Main entry point with auto-build
- **ui/** - React Ink terminal UI (TypeScript)
- **src/modules/** - Python backend (core, parsers, tools, cli, utils)
- **output/** - Generated files (attack trees, logs, state)

## Benefits of New Structure

✅ **Single Command**: `python threatforest.py` - that's it!  
✅ **Auto-Build**: UI builds automatically on first run  
✅ **Clean Separation**: src, tests, output, docs, ui  
✅ **Professional**: Follows Python best practices  
✅ **Easy Navigation**: Clear folder hierarchy  
✅ **Resume Capability**: State checkpoints for recovery  
✅ **Modern UI**: React Ink terminal interface  

## Next Steps

1. Run `python threatforest.py`
2. Follow the interactive wizard
3. View generated attack trees in `output/attack_trees/`
4. Check logs in `output/logs/` if needed
5. Resume from checkpoint with `python threatforest.py resume`


### Cache Management

```bash
python -m src.modules.cli.cache_manager info
python -m src.modules.cli.cache_manager stats
python -m src.modules.cli.cache_manager clear
```

## Import Examples

```python
# Import from core
from src.modules.core import cache, bedrock_service

# Import from parsers
from src.modules.parsers import chain

# Import from tools
from src.modules.tools import setup_tool
```

## Output Files

- **Attack Trees**: `output/attack_trees/`
- **Logs**: `output/logs/threatforest.log`
- **State**: `output/state/workflow_state.json`

## Benefits

- ✅ Clean separation of concerns
- ✅ Single command entry point
- ✅ Professional Python structure
- ✅ Easy to navigate and maintain
- ✅ Dedicated output directories
