# ThreatForest - New Folder Structure

## Quick Start

Run ThreatForest with a single command:

```bash
python threatforest.py
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

## Installation

### Development Mode

```bash
pip install -e .
```

### Dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Run ThreatForest

```bash
python threatforest.py
```

### Run Tests

```bash
python -m pytest tests/ -v
```

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
