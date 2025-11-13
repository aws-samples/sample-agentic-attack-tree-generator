# Task 0.2: src/ Module Usage Analysis

**Backlog Reference**: [docs/Backlog.md - Task 0.2](../Backlog.md#task-02-analyze-src-module-usage)

## Objective
Identify which modules in src/ are actually used vs. dead code.

## Module Usage Matrix

### Core Modules (src/modules/core/)
- ✅ **bedrock_client.py** - Used by setup_tool, information_extraction_tool, bedrock_service
- ✅ **bedrock_service.py** - Exported in core/__init__.py
- ✅ **bedrock_invoker.py** - Used by attack_tree_generator_tool, ttc_mapping_tool
- ✅ **base_agent.py** - Used by strands_agent (Agent, agent_step)
- ✅ **base_tool.py** - Used by all tools (Tool, tool decorator)
- ✅ **context.py** - Used by strands_agent (Context)
- ✅ **error_handler.py** - Exported in core/__init__.py
- ✅ **errors.py** - Used by error_handler
- ✅ **file_discovery.py** - Called from UI + used by context_analysis_tool
- ✅ **parallel.py** - Used by pipeline (ParallelExecutor, ParallelTask)
- ✅ **pipeline.py** - Exported in core/__init__.py (Pipeline, Stage)
- ✅ **progress_emitter.py** - Used by strands_agent (ProgressEmitter)
- ✅ **progress_events.py** - Used by progress_emitter + strands_agent
- ✅ **rate_limiter.py** - Used by bedrock_service
- ✅ **retry.py** - Exported in core/__init__.py
- ✅ **state.py** - Called from UI + used by state_manager, pipeline
- ✅ **state_manager.py** - Called from UI + used by strands_agent
- ✅ **validation.py** - Called from UI + exported in core/__init__.py

**Result**: ALL 18 core modules are USED ✅

### Tools (src/modules/tools/)
- ✅ **attack_tree_generator_tool.py** - Called from UI + used by strands_agent
- ✅ **context_analysis_tool.py** - Called from UI + used by strands_agent, wizard
- ✅ **information_extraction_tool.py** - Called from UI + used by strands_agent, wizard
- ✅ **summary_generator_tool.py** - Called from UI + used by strands_agent, wizard
- ✅ **setup_tool.py** - Used by strands_agent, wizard
- ✅ **ttc_mapping_tool.py** - Used by strands_agent, wizard
- ❌ **threat_jq.sh** - Shell script, no Python imports found

**Result**: 6/7 tools USED, 1 needs investigation (threat_jq.sh)

### Parsers (src/modules/parsers/)
- ✅ **base.py** - Base class for all parsers
- ✅ **chain.py** - Used by information_extraction_tool (ParserChain)
- ✅ **json_parser.py** - Used by information_extraction_tool (JSONThreatParser)
- ✅ **markdown_parser.py** - Used by information_extraction_tool (MarkdownThreatParser)
- ✅ **yaml_parser.py** - Used by information_extraction_tool (YAMLThreatParser)
- ✅ **threatcomposer_parser.py** - Used by information_extraction_tool (ThreatComposerParser)

**Result**: ALL 6 parsers are USED ✅

### TTC Mappings (src/modules/ttc_mappings/)
- ✅ **__init__.py** - Exports TTCMatcher, AttackTreeEnricher, MitigationEnricher
- ✅ **matcher.py** - Called from UI (via __init__)
- ✅ **enricher.py** - Called from UI (via __init__)
- ✅ **mitigation_enricher.py** - Exported in __init__.py
- ✅ **mitigation_mapper.py** - Called from UI
- ❌ **cli.py** - Standalone CLI (imports matcher, enricher)
- ❌ **example.py** - Example code (imports matcher, enricher)
- ❌ **demo_mitigations.py** - Demo code
- ❌ **mitigation_cli.py** - Standalone CLI
- ❌ **map_mitigations.py** - Standalone script

**Result**: 5/10 USED, 5 are standalone utilities/examples

### Utils (src/modules/utils/)
- ✅ **logger.py** - Called from UI + used by all tools

**Result**: 1/1 USED ✅

### CLI (src/modules/cli/)
- ❓ **__init__.py** - Empty file, no imports

**Result**: 0/1 USED (empty directory)

### Root Source Files (src/)
- ✅ **strands_agent.py** - Called from UI (ThreatForestOrchestrator)
- ✅ **wizard.py** - Imports all tools, may be used for CLI mode
- ✅ **config.py** - Called from UI
- ❌ **threatforest_wizard.py** - Empty/stub file (no imports)
- ✅ **test_wizard_ttc.py** - Test file (KEEP)
- ✅ **test_wizard_modes.py** - Test file (KEEP)

**Result**: 4/6 USED (excluding tests), 1 stub file

## Import Dependency Graph

```
strands_agent.py (ENTRY POINT)
├── modules.core
│   ├── Agent, agent_step (base_agent.py)
│   ├── Context (context.py)
│   ├── ThreatForestState, WorkflowStage (state.py)
│   ├── StateManager (state_manager.py)
│   ├── ProgressEmitter (progress_emitter.py)
│   ├── ProgressEvent, ProgressEventType (progress_events.py)
│   └── Tool, tool (base_tool.py)
├── modules.tools.setup_tool → SetupTool
│   ├── utils.logger → ThreatForestLogger
│   ├── core → Tool, tool
│   └── core.bedrock_client → BedrockClientManager
├── modules.tools.context_analysis_tool → ContextAnalysisTool
│   ├── utils.logger → ThreatForestLogger
│   ├── core → Tool, tool, FileDiscovery
│   └── core.file_discovery → FileDiscovery
├── modules.tools.information_extraction_tool → InformationExtractionTool
│   ├── utils.logger → ThreatForestLogger
│   ├── core → Tool, tool
│   ├── core.bedrock_client → BedrockClientManager
│   └── parsers → ParserChain, JSONThreatParser, YAMLThreatParser, MarkdownThreatParser, ThreatComposerParser
│       └── parsers.base → ThreatParser
├── modules.tools.attack_tree_generator_tool → AttackTreeGeneratorTool
│   ├── utils.logger → ThreatForestLogger
│   ├── core → Tool, tool
│   └── core.bedrock_invoker → BedrockInvoker
│       └── core.bedrock_client → BedrockClientManager
├── modules.tools.ttc_mapping_tool → TTCMappingTool
│   ├── utils.logger → ThreatForestLogger
│   ├── core → Tool, tool
│   └── core.bedrock_invoker → BedrockInvoker
└── modules.tools.summary_generator_tool → SummaryGeneratorTool
    ├── utils.logger → ThreatForestLogger
    └── core → Tool, tool

wizard.py (ALTERNATE ENTRY)
├── modules.utils.logger → ThreatForestLogger
└── (same tools as strands_agent)

UI Python Bridge Calls:
├── ttc_mappings → TTCMatcher, AttackTreeEnricher
│   ├── matcher.py (no local imports)
│   └── enricher.py (no local imports)
├── ttc_mappings.mitigation_mapper → MitigationMapper
│   └── (no local imports)
├── config → config
│   └── (no local imports)
├── core.file_discovery → FileDiscovery
├── core.state_manager → StateManager
│   └── state → ThreatForestState, WorkflowStage
├── core.state → ThreatForestState
└── core.validation → (dynamic classes)

Bedrock Client Chain:
bedrock_client.py (BedrockClientManager)
└── bedrock_service.py (BedrockService)
    └── rate_limiter.py (BedrockRateLimiter)

bedrock_invoker.py (BedrockInvoker)
└── bedrock_client.py (BedrockClientManager)
```

## Summary Statistics

### USED Modules: 40
- Core: 18/18 ✅
- Tools: 6/7 ✅
- Parsers: 6/6 ✅
- TTC Mappings: 5/10 ✅
- Utils: 1/1 ✅
- Root: 4/6 ✅

### UNUSED/STANDALONE: 8
- **Standalone CLIs/Scripts** (5):
  - ttc_mappings/cli.py
  - ttc_mappings/mitigation_cli.py
  - ttc_mappings/map_mitigations.py
  - ttc_mappings/example.py
  - ttc_mappings/demo_mitigations.py

- **Needs Investigation** (2):
  - tools/threat_jq.sh (shell script)
  - modules/cli/ (empty directory)

- **Dead Code** (1):
  - src/threatforest_wizard.py (empty stub)

## Removal Candidates

### High Confidence - Dead Code:
1. **src/threatforest_wizard.py** - Empty stub file, no imports, not used

### Medium Confidence - Standalone Utilities:
These are NOT imported by main application but may be useful standalone tools:
1. **src/modules/ttc_mappings/cli.py** - Standalone CLI for TTC matching
2. **src/modules/ttc_mappings/mitigation_cli.py** - Standalone CLI for mitigations
3. **src/modules/ttc_mappings/map_mitigations.py** - Standalone script
4. **src/modules/ttc_mappings/example.py** - Example code
5. **src/modules/ttc_mappings/demo_mitigations.py** - Demo code

### Needs Investigation:
1. **src/modules/tools/threat_jq.sh** - Shell script, check if called by any tool
2. **src/modules/cli/** - Empty directory, safe to remove if truly empty
3. **src/wizard.py** - Imports all tools, may be alternate entry point for CLI mode

## Deliverables
- ✅ Complete module usage matrix
- ✅ Import dependency graph
- ✅ List of candidate modules for removal (8 candidates)

## Notes
- **wizard.py** needs clarification: Is it used for CLI mode or replaced by UI?
- All core modules are interconnected and used
- All parsers are used by information_extraction_tool
- TTC mapping utilities are separate from main workflow
- Consider keeping standalone CLIs as utilities even if not in main flow
