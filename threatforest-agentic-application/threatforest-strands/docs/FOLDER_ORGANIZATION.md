# ThreatForest Folder Organization

## Main Directory Structure

```
threatforest-strands/
├── threatforest.py          # Main entry point - run this!
├── setup.py                 # Package installation
├── requirements.txt         # Python dependencies
├── pyproject.toml          # Project configuration
├── README.md               # Main documentation
│
├── src/                    # Source code
│   ├── modules/
│   │   ├── core/          # Core functionality
│   │   ├── parsers/       # Threat parsers
│   │   ├── tools/         # Strands tools
│   │   ├── cli/           # CLI utilities
│   │   └── utils/         # Utilities
│   ├── strands_agent.py   # Main orchestrator
│   └── wizard.py          # Interactive wizard
│
├── tests/                  # All tests
│   ├── validation-parsing/
│   ├── performance-optimization/
│   └── infrastructure-reliability/
│
├── output/                 # Generated output
│   ├── attack_trees/      # Attack tree files
│   ├── logs/              # Application logs
│   └── state/             # State checkpoints
│
├── ui/                     # React Ink terminal UI
│   ├── src/
│   ├── dist/
│   └── package.json
│
├── docs/                   # Documentation
│   ├── README_NEW_STRUCTURE.md
│   ├── improvements.md
│   ├── CLI_USAGE.md
│   ├── OVERVIEW.md
│   ├── prompts/           # AI prompts
│   └── [group-folders]/   # Group-specific docs
│
├── stix-data/             # STIX threat data
│
├── archive/               # Archived/deprecated files
│   ├── threatforest/      # Old folder structure
│   ├── scripts/           # Old scripts
│   └── __init__.py        # Old files
│
└── tf-venv/               # Virtual environment (gitignored)
```

## Key Files

### Essential Files
- `threatforest.py` - Main entry point
- `setup.py` - Package configuration
- `requirements.txt` - Dependencies
- `README.md` - Main documentation

### Documentation
- `docs/README_NEW_STRUCTURE.md` - New structure guide
- `docs/improvements.md` - Implementation tracking
- `docs/CLI_USAGE.md` - CLI usage guide
- `docs/OVERVIEW.md` - Project overview

### Configuration
- `pyproject.toml` - Project metadata

## Archived Items

The `archive/` folder contains:
- Old `threatforest/` folder structure (before reorganization)
- Old scripts from `scripts/` folder
- Deprecated files (`__init__.py`, `threatforest_wizard.py`)

These are kept for reference but not used in the new structure.

## Usage

### Run Application
```bash
python threatforest.py
```

### Install Package
```bash
pip install -e .
```

### Run Tests
```bash
python -m pytest tests/ -v
```

## Clean Structure Benefits

✅ Single entry point (`threatforest.py`)  
✅ Clear separation: src, tests, output, docs  
✅ Professional Python structure  
✅ Easy to navigate  
✅ Archived old files for reference  
