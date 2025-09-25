# ThreatForest Strands Implementation

This directory contains the new Strands-based implementation of ThreatForest, built as an agentic AI system for automated attack tree generation.

## Structure

```
threatforest-strands/
├── threatforest/
│   ├── strands_agent.py          # Main orchestrator agent
│   ├── strands_cli.py           # CLI entry point
│   └── tools/                   # Specialized tools
│       ├── setup_tool.py        # Environment validation
│       ├── context_analysis_tool.py  # File discovery
│       ├── information_extraction_tool.py  # Threat parsing & Bedrock extraction
│       ├── attack_tree_generator_tool.py   # Mermaid generation
│       ├── ttc_mapping_tool.py  # STIX integration (stub)
│       └── summary_generator_tool.py       # Report generation (stub)
└── tests/                       # Test scripts
    ├── simple_test.py          # Context analysis test
    ├── test_extraction.py      # Threat parsing test
    ├── test_bedrock_integration.py  # Bedrock API test
    └── test_full_bedrock.py    # Complete integration test
```

## Key Features

- **Single Orchestrating Agent**: `ThreatForestOrchestrator` coordinates all workflow steps
- **Specialized Tools**: Each tool handles a specific aspect of the workflow
- **Real Bedrock Integration**: Uses Claude Opus 4.1 for project information extraction
- **Threat Parsing**: Correctly parses 37 threats with 9 high severity from example
- **User Validation**: Interactive validation of extracted project information
- **Output Structure**: Generates files in `outputs/{application_name}/` directory

## Usage

```bash
# Run tests
cd threatforest-strands/tests
python test_full_bedrock.py

# Run CLI (when complete)
python -m threatforest.strands_cli --project-path /path/to/project
```

## Status

✅ **Working Components**:
- Context analysis and file discovery
- Threat statement parsing with severity detection
- Bedrock API integration for project information extraction
- User validation workflow

🔄 **In Progress**:
- Attack tree generation with Mermaid output
- TTC mapping with STIX integration
- Complete summary generation

## Separation from Original Code

This implementation is completely separate from the original ThreatForest codebase in the parent directory. It uses the Strands framework for agentic AI orchestration and provides a clean, modular architecture for attack tree generation.
