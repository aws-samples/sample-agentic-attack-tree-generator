# ThreatForest Strands - Technical Debt Backlog

## Overview
This backlog tracks technical debt items related to configuration consistency, maintainability, and best practices across the ThreatForest Strands application.

## Priority Requirements

### 0. **[HIGHEST PRIORITY]** Dead Code Elimination & Unused Module Cleanup
**Goal**: Identify and remove all unused modules, files, and code paths that are not invoked by the application entry points.

### 1. Consistent Bedrock Model Handling
**Goal**: All Bedrock model IDs should be sourced from a central configuration, not hardcoded in individual files.

### 2. Dynamic Region Management
**Goal**: AWS region should be dynamically determined from AWS credentials/profile, not hardcoded as 'us-east-1' or 'us-west-2'.

### 3. Externalized Prompts
**Goal**: All LLM prompts should be stored in `src/prompts/` folder and loaded at runtime, not embedded in Python code.

---

## Task List

### Phase 0: Dead Code Elimination & Unused Module Cleanup 🔥

**Objective**: Perform comprehensive code analysis to identify and remove unused modules, files, and code that are not part of the active execution paths. This is NOT a refactoring exercise - only removal of dead code.

**Entry Points:**
- Primary: `threatforest.py` → launches React UI (`ui/dist/cli.js`)
- Setup: `setup.sh` → installs dependencies and builds UI
- UI Bridge: `ui/src/utils/pythonBridge.ts` → calls Python modules

**Scope:**
- `src/` - All Python source modules
- `data/` - Data files and embeddings
- `embedding-tools/` - Embedding generation and matching tools
- `ui/` - React TypeScript UI components

---

#### Task 0.1: Map Application Entry Points and Execution Flow
**Status**: ✅ Complete  
**Priority**: Critical  
**Effort**: 4 hours

**Working Document**: `docs/phase0/task_0.1_entry_points.md`

**Setup Instructions:**
```bash
mkdir -p docs/phase0
cat > docs/phase0/task_0.1_entry_points.md << 'EOF'
# Task 0.1: Entry Points and Execution Flow Analysis

**Backlog Reference**: [docs/Backlog.md - Task 0.1](../Backlog.md#task-01-map-application-entry-points-and-execution-flow)

## Objective
Create a complete execution flow diagram from entry points to all reachable code.

## Analysis Results

### 1. Primary Entry Point Analysis
- [ ] TODO: Document threatforest.py → UI flow

### 2. E2E Test Analysis
- [ ] TODO: Document orchestrator flow

### 3. Python Bridge Analysis
- [ ] TODO: List all pythonBridge.execute() calls

### 4. Direct Python Imports
- [ ] TODO: Document strands_agent.py dependencies

## Deliverables
- [ ] Execution flow diagram (Mermaid)
- [ ] List of reachable Python modules
- [ ] List of reachable UI components
- [ ] Data flow documentation
EOF
```

**Objective**: Create a complete execution flow diagram from entry points to all reachable code.

**Analysis Steps:**

1. **Primary Entry Point Analysis**
   - [ ] Trace `threatforest.py` → `ui/dist/cli.js` → `ui/src/` components
   - [ ] Document UI component tree and state flow
   - [ ] Identify all `pythonBridge.execute()` calls in UI

2. **E2E Test Analysis (Supplementary)**
   - [ ] Run `tests/automated_e2e_test.py` to observe direct orchestrator flow
   - [ ] Document modules called by `ThreatForestOrchestrator.run()`
   - [ ] Note: E2E test bypasses UI, shows core workflow only
   - [ ] Compare E2E flow vs. UI flow to identify UI-specific modules
   
   **E2E Test Entry Point:**
   ```python
   # tests/automated_e2e_test.py
   from strands_agent import ThreatForestOrchestrator, ThreatForestConfig
   
   config = ThreatForestConfig(
       project_path=project_path,
       output_dir=output_dir,
       aws_profile=profile,
       bedrock_model=model_id
   )
   orchestrator = ThreatForestOrchestrator(config)
   result = await orchestrator.run()
   ```
   
   **Use E2E Test For:**
   - Understanding core orchestrator workflow
   - Identifying modules used in headless mode
   - Validating which tools are actually invoked
   - Testing after removal phases
   
   **Do NOT Use E2E Test For:**
   - UI component analysis (bypasses UI entirely)
   - Wizard flow analysis (uses direct orchestrator)
   - Python bridge analysis (no bridge in E2E)

3. **Python Bridge Analysis**
   - [ ] Extract all Python module imports from `ui/src/utils/pythonBridge.ts`
   - [ ] Document which classes and methods are called from UI
   - [ ] Map Python execution paths from bridge calls

4. **Direct Python Imports**
   - [ ] Analyze `src/strands_agent.py` imports and dependencies
   - [ ] Analyze `src/wizard.py` imports and dependencies
   - [ ] Analyze `src/config.py` usage across codebase

**Known UI → Python Calls (from pythonBridge.ts):**
```
Line 99:  src.modules.ttc_mappings → TTCMatcher, AttackTreeEnricher
Line 189: src.modules.ttc_mappings.mitigation_mapper → MitigationMapper
Line 190: src.config → config
Line 289: src.modules.core.file_discovery → FileDiscovery
Line 348: src.modules.core.state_manager → StateManager
Line 395: src.modules.core.state_manager → StateManager
Line 396: src.modules.core.state → ThreatForestState
Line 459: src.modules.core.validation → [dynamic class]
Line 686: src.modules.utils.logger → ThreatForestLogger
Line 687: src.modules.tools.context_analysis_tool → ContextAnalysisTool
Line 760: src.modules.tools.information_extraction_tool → InformationExtractionTool
Line 841: src.modules.tools.attack_tree_generator_tool → AttackTreeGeneratorTool
Line 1003: src.modules.tools.summary_generator_tool → SummaryGeneratorTool
Line 1087: src.strands_agent → ThreatForestOrchestrator, ThreatForestConfig
```

**Deliverables:**
- [ ] Execution flow diagram (Mermaid or similar)
- [ ] List of all reachable Python modules from entry points
- [ ] List of all reachable UI components
- [ ] Documentation of data flow between UI and Python

---

#### Task 0.2: Analyze src/ Module Usage
**Status**: ✅ Complete  
**Priority**: Critical  
**Effort**: 6 hours

**Working Document**: `docs/phase0/task_0.2_module_usage.md`

**Setup Instructions:**
```bash
cat > docs/phase0/task_0.2_module_usage.md << 'EOF'
# Task 0.2: src/ Module Usage Analysis

**Backlog Reference**: [docs/Backlog.md - Task 0.2](../Backlog.md#task-02-analyze-src-module-usage)

## Objective
Identify which modules in src/ are actually used vs. dead code.

## Module Usage Matrix

### Core Modules (src/modules/core/)
- [ ] bedrock_client.py - ✓/✗
- [ ] bedrock_service.py - ✓/✗
- [ ] bedrock_invoker.py - ✓/✗
- [ ] base_agent.py - ✓/✗
- [ ] base_tool.py - ✓/✗
- [ ] context.py - ✓/✗
- [ ] error_handler.py - ✓/✗
- [ ] errors.py - ✓/✗
- [ ] file_discovery.py - ✓ (Called from UI)
- [ ] parallel.py - ✓/✗
- [ ] pipeline.py - ✓/✗
- [ ] progress_emitter.py - ✓/✗
- [ ] progress_events.py - ✓/✗
- [ ] rate_limiter.py - ✓/✗
- [ ] retry.py - ✓/✗
- [ ] state.py - ✓ (Called from UI)
- [ ] state_manager.py - ✓ (Called from UI)
- [ ] validation.py - ✓ (Called from UI)

### Tools (src/modules/tools/)
- [ ] attack_tree_generator_tool.py - ✓ (Called from UI)
- [ ] context_analysis_tool.py - ✓ (Called from UI)
- [ ] information_extraction_tool.py - ✓ (Called from UI)
- [ ] summary_generator_tool.py - ✓ (Called from UI)
- [ ] setup_tool.py - ✓/✗
- [ ] ttc_mapping_tool.py - ✓/✗
- [ ] threat_jq.sh - ✓/✗

### Parsers (src/modules/parsers/)
- [ ] base.py - ✓/✗
- [ ] chain.py - ✓/✗
- [ ] json_parser.py - ✓/✗
- [ ] markdown_parser.py - ✓/✗
- [ ] yaml_parser.py - ✓/✗
- [ ] threatcomposer_parser.py - ✓/✗

### TTC Mappings (src/modules/ttc_mappings/)
- [ ] __init__.py - ✓/✗
- [ ] cli.py - ✓/✗
- [ ] enricher.py - ✓/✗
- [ ] matcher.py - ✓/✗
- [ ] example.py - ✓/✗
- [ ] demo_mitigations.py - ✓/✗
- [ ] mitigation_cli.py - ✓/✗
- [ ] mitigation_enricher.py - ✓/✗
- [ ] mitigation_mapper.py - ✓ (Called from UI)
- [ ] map_mitigations.py - ✓/✗

### Utils (src/modules/utils/)
- [ ] logger.py - ✓ (Called from UI)

### Root Source Files (src/)
- [ ] strands_agent.py - ✓ (Called from UI)
- [ ] wizard.py - ✓/✗
- [ ] config.py - ✓ (Called from UI)
- [ ] threatforest_wizard.py - ✓/✗

## Import Dependency Graph
TODO: Add graph here

## Deliverables
- [ ] Complete module usage matrix
- [ ] Import dependency graph
- [ ] List of candidate modules for removal
EOF
```

**Objective**: Identify which modules in `src/` are actually used vs. dead code.

**Analysis Approach:**

1. **Static Import Analysis**
   - [ ] Run import graph analysis starting from known entry points
   - [ ] Use Python AST parsing to build dependency tree
   - [ ] Identify circular dependencies
   - [ ] Flag modules with zero incoming references

2. **Module-by-Module Analysis**

   **Core Modules (`src/modules/core/`):**
   - [ ] `bedrock_client.py` - Used by tools? ✓/✗
   - [ ] `bedrock_service.py` - Used by tools? ✓/✗
   - [ ] `bedrock_invoker.py` - Used by tools? ✓/✗
   - [ ] `base_agent.py` - Used by strands_agent? ✓/✗
   - [ ] `base_tool.py` - Used by tools? ✓/✗
   - [ ] `context.py` - Used by agents? ✓/✗
   - [ ] `error_handler.py` - Used by tools? ✓/✗
   - [ ] `errors.py` - Used by error_handler? ✓/✗
   - [ ] `file_discovery.py` - Called from UI ✓
   - [ ] `parallel.py` - Used by agents? ✓/✗
   - [ ] `pipeline.py` - Used by agents? ✓/✗
   - [ ] `progress_emitter.py` - Used by tools? ✓/✗
   - [ ] `progress_events.py` - Used by progress_emitter? ✓/✗
   - [ ] `rate_limiter.py` - Used by bedrock clients? ✓/✗
   - [ ] `retry.py` - Used by bedrock clients? ✓/✗
   - [ ] `state.py` - Called from UI ✓
   - [ ] `state_manager.py` - Called from UI ✓
   - [ ] `validation.py` - Called from UI ✓

   **Tools (`src/modules/tools/`):**
   - [ ] `attack_tree_generator_tool.py` - Called from UI ✓
   - [ ] `context_analysis_tool.py` - Called from UI ✓
   - [ ] `information_extraction_tool.py` - Called from UI ✓
   - [ ] `summary_generator_tool.py` - Called from UI ✓
   - [ ] `setup_tool.py` - Used by wizard? ✓/✗
   - [ ] `ttc_mapping_tool.py` - Used by UI/wizard? ✓/✗
   - [ ] `threat_jq.sh` - Called by any tool? ✓/✗

   **Parsers (`src/modules/parsers/`):**
   - [ ] `base.py` - Base class for parsers? ✓/✗
   - [ ] `chain.py` - Used by tools? ✓/✗
   - [ ] `json_parser.py` - Used by tools? ✓/✗
   - [ ] `markdown_parser.py` - Used by tools? ✓/✗
   - [ ] `yaml_parser.py` - Used by tools? ✓/✗
   - [ ] `threatcomposer_parser.py` - Used by tools? ✓/✗

   **TTC Mappings (`src/modules/ttc_mappings/`):**
   - [ ] `__init__.py` - Exports used classes? ✓/✗
   - [ ] `cli.py` - Standalone CLI? ✓/✗
   - [ ] `enricher.py` - Used by UI? ✓/✗
   - [ ] `matcher.py` - Used by UI? ✓/✗
   - [ ] `example.py` - Example/demo code? ✓/✗
   - [ ] `demo_mitigations.py` - Demo code? ✓/✗
   - [ ] `mitigation_cli.py` - Standalone CLI? ✓/✗
   - [ ] `mitigation_enricher.py` - Used by UI? ✓/✗
   - [ ] `mitigation_mapper.py` - Called from UI ✓
   - [ ] `map_mitigations.py` - Standalone script? ✓/✗

   **Utils (`src/modules/utils/`):**
   - [ ] `logger.py` - Called from UI ✓

   **CLI (`src/modules/cli/`):**
   - [ ] Identify all files in this directory
   - [ ] Check if any are called from UI or entry points

   **Root Source Files (`src/`):**
   - [ ] `strands_agent.py` - Called from UI ✓
   - [ ] `wizard.py` - Used by UI? ✓/✗
   - [ ] `config.py` - Called from UI ✓
   - [ ] `threatforest_wizard.py` - Duplicate/old? ✓/✗
   - [ ] `test_wizard_ttc.py` - Test file (keep)
   - [ ] `test_wizard_modes.py` - Test file (keep)

**Deliverables:**
- [ ] Complete module usage matrix (Used ✓ / Unused ✗)
- [ ] Import dependency graph
- [ ] List of candidate modules for removal

---

#### Task 0.3: Analyze data/ and embedding-tools/ Usage
**Status**: ✅ Complete  
**Priority**: High  
**Effort**: 3 hours

**Working Document**: `docs/phase0/task_0.3_data_embeddings.md`

**Setup Instructions:**
```bash
cat > docs/phase0/task_0.3_data_embeddings.md << 'EOF'
# Task 0.3: Data & Embedding Tools Analysis

**Backlog Reference**: [docs/Backlog.md - Task 0.3](../Backlog.md#task-03-analyze-data-and-embedding-tools-usage)

## Confirmed Information
- ✅ Embeddings are pre-computed
- ✅ Active model: qwen
- ✅ Embedding tools are separate utilities

## Data Files Analysis
- [ ] TODO: Document which files in data/ are loaded

## Embedding Files Status
- ✅ KEEP: attack_pattern_embeddings_qwen.json (6.9 MB)
- ❌ REMOVE: attack_pattern_embeddings_mpnet.json (5.2 MB)
- ❌ REMOVE: attack_pattern_embeddings.json (5.3 MB)
- ❌ REMOVE: attack_pattern_embeddings_qwen4b.json (16.9 MB)
- ❌ REMOVE: cm (0 bytes)

## Embedding Tools Status
All tools in embedding-tools/ are KEPT as separate utilities.

## Deliverables
- [ ] List of actively used data files
- [ ] Confirmed removal list (~27 MB)
EOF
```

**Objective**: Determine which data files and embedding tools are actively used.

**Confirmed Information:**
- ✅ Embeddings are **pre-computed** (not generated at runtime)
- ✅ Active embedding model: **qwen** (not mpnet or qwen4b)
- ✅ Embedding tools are **separate utilities** (not part of main workflow)

**Data Directory Analysis (`data/`):**
- [ ] `data/embeddings/` - Check if loaded by any module
- [ ] Identify which embedding files are referenced in code
- [ ] Verify only `attack_pattern_embeddings_qwen.json` is loaded
- [ ] Check if data files are hardcoded or config-driven

**Embedding Tools Analysis (`embedding-tools/`):**

**Files to KEEP (Separate Utilities):**
- [ ] `cli.py` - Standalone utility ✓
- [ ] `create_embeddings.py` - Utility for generating embeddings ✓
- [ ] `match_attack_steps.py` - Utility for matching ✓
- [ ] `match_attack_steps_improved.py` - Improved matching utility ✓
- [ ] `compare_models.py` - Model comparison utility ✓
- [ ] `load_matches.py` - Utility for loading matches ✓
- [ ] `test_matching_improvements.py` - Test file ✓
- [ ] `*.md` documentation files - Keep for reference ✓

**Files to EVALUATE for Removal:**
- [ ] `attack_pattern_embeddings_mpnet.json` - Unused model (5.2 MB) ❌
- [ ] `attack_pattern_embeddings.json` - Duplicate/old? (5.3 MB) ❌
- [ ] `attack_pattern_embeddings_qwen4b.json` - Unused model (16.9 MB) ❌
- [ ] `attack_step_matches.json` - Old matches? (138 KB) ❓
- [ ] `attack-trees/` directory - Sample data or active? ❓
- [ ] `cm` - Empty file (0 bytes) ❌

**Files to KEEP (Active):**
- [ ] `attack_pattern_embeddings_qwen.json` - Active embedding model (6.9 MB) ✓

**Removal Candidates (Unused Embeddings):**
```
embedding-tools/attack_pattern_embeddings_mpnet.json     (5.2 MB)
embedding-tools/attack_pattern_embeddings.json           (5.3 MB)  
embedding-tools/attack_pattern_embeddings_qwen4b.json    (16.9 MB)
embedding-tools/cm                                       (0 bytes)
Total: ~27.4 MB
```

**Questions to Answer:**
- ✅ Are embeddings generated at runtime or pre-computed? **Pre-computed**
- ✅ Which embedding model is actively used? **qwen**
- ✅ Are embedding tools part of main workflow? **No, separate utilities**
- [ ] Is `attack_step_matches.json` used or can it be regenerated?
- [ ] Is `attack-trees/` directory needed or just examples?
- [ ] Should unused embeddings be deleted or archived?

**Deliverables:**
- [ ] List of actively used data files
- [ ] List of actively used embedding tools (all kept as utilities)
- [ ] List of unused/redundant embedding files (~27 MB)
- [ ] Recommendation: Delete unused embeddings or move to archive

---

#### Task 0.4: Analyze UI Component Usage
**Status**: ✅ Complete  
**Priority**: High  
**Effort**: 3 hours

**Working Document**: `docs/phase0/task_0.4_ui_components.md`

**Setup Instructions:**
```bash
cat > docs/phase0/task_0.4_ui_components.md << 'EOF'
# Task 0.4: UI Component Usage Analysis

**Backlog Reference**: [docs/Backlog.md - Task 0.4](../Backlog.md#task-04-analyze-ui-component-usage)

## Component Usage Matrix

### Components (ui/src/components/)
- [ ] App.tsx - ✓
- [ ] WelcomeScreen.tsx - ✓/✗
- [ ] ConfigurationScreen.tsx - ✓/✗
- [ ] ModeSelector.tsx - ✓/✗
- [ ] PathSelector.tsx - ✓/✗
- [ ] ProgressScreen.tsx - ✓/✗
- [ ] ProgressDetails.tsx - ✓/✗
- [ ] SummaryScreen.tsx - ✓/✗
- [ ] ContinuePrompt.tsx - ✓/✗

### Hooks (ui/src/hooks/)
- [ ] useWorkflow.ts - ✓/✗

### Utils (ui/src/utils/)
- [ ] pythonBridge.ts - ✓

## Component Tree
TODO: Add component tree diagram

## Deliverables
- [ ] Component usage tree
- [ ] List of unused components
- [ ] List of unused utilities
EOF
```

**Objective**: Identify unused React components and utilities in `ui/src/`.

**UI Structure Analysis:**
- [ ] Map component tree from `App.tsx`
- [ ] Identify all imported components
- [ ] Check for orphaned components (no imports)
- [ ] Verify all utilities in `ui/src/utils/` are used

**Component Analysis (`ui/src/components/`):**
- [ ] `App.tsx` - Main component ✓
- [ ] `WelcomeScreen.tsx` - Used by App? ✓/✗
- [ ] `ConfigurationScreen.tsx` - Used by App? ✓/✗
- [ ] `ModeSelector.tsx` - Used by App? ✓/✗
- [ ] `PathSelector.tsx` - Used by App? ✓/✗
- [ ] `ProgressScreen.tsx` - Used by App? ✓/✗
- [ ] `ProgressDetails.tsx` - Used by ProgressScreen? ✓/✗
- [ ] `SummaryScreen.tsx` - Used by App? ✓/✗
- [ ] `ContinuePrompt.tsx` - Used by App? ✓/✗

**Hooks Analysis (`ui/src/hooks/`):**
- [ ] `useWorkflow.ts` - Used by components? ✓/✗

**Utils Analysis (`ui/src/utils/`):**
- [ ] `pythonBridge.ts` - Used by hooks/components ✓

**Deliverables:**
- [ ] Component usage tree diagram
- [ ] List of unused components
- [ ] List of unused utilities

---

#### Task 0.5: Identify Test Files vs. Production Code
**Status**: ✅ Complete  
**Priority**: Medium  
**Effort**: 2 hours

**Working Document**: `docs/phase0/task_0.5_test_files.md`

**Setup Instructions:**
```bash
cat > docs/phase0/task_0.5_test_files.md << 'EOF'
# Task 0.5: Test Files Identification

**Backlog Reference**: [docs/Backlog.md - Task 0.5](../Backlog.md#task-05-identify-test-files-vs-production-code)

## Test Files to Preserve

### Known Test Files
- [ ] src/test_wizard_ttc.py
- [ ] src/test_wizard_modes.py
- [ ] tests/ (entire directory)
- [ ] embedding-tools/test_matching_improvements.py

### Example/Demo Files (Evaluate)
- [ ] src/modules/ttc_mappings/example.py
- [ ] src/modules/ttc_mappings/demo_mitigations.py

## Deliverables
- [ ] Complete list of test files (DO NOT REMOVE)
- [ ] Complete list of example/demo files (EVALUATE)
EOF
```

**Objective**: Clearly separate test files from production code to avoid accidental removal.

**Test File Patterns:**
- Files starting with `test_`
- Files in `tests/` directory
- Files ending with `_test.py`
- Demo/example files

**Files to Preserve (Tests & Examples):**
- [ ] `src/test_wizard_ttc.py`
- [ ] `src/test_wizard_modes.py`
- [ ] `tests/` directory (entire)
- [ ] `embedding-tools/test_matching_improvements.py`
- [ ] `src/modules/ttc_mappings/example.py` (if example)
- [ ] `src/modules/ttc_mappings/demo_mitigations.py` (if demo)

**Deliverables:**
- [ ] Complete list of test files (DO NOT REMOVE)
- [ ] Complete list of example/demo files (EVALUATE)
- [ ] Clear marking in removal candidates list

---

#### Task 0.6: Create Removal Candidate List
**Status**: ✅ Complete  
**Priority**: High  
**Effort**: 2 hours

**Working Document**: `docs/phase0/task_0.6_removal_candidates.md`

**Setup Instructions:**
```bash
cat > docs/phase0/task_0.6_removal_candidates.md << 'EOF'
# Task 0.6: Removal Candidate List

**Backlog Reference**: [docs/Backlog.md - Task 0.6](../Backlog.md#task-06-create-removal-candidate-list)

## High Confidence (No references found)
- [ ] TODO: List modules with zero imports

## Medium Confidence (Verify manually)
- [ ] TODO: List modules only imported by unused code

## Low Confidence (Needs investigation)
- [ ] TODO: List modules with unclear usage

## Confirmed Removals
### Embedding Files (~27 MB)
- embedding-tools/attack_pattern_embeddings_mpnet.json (5.2 MB)
- embedding-tools/attack_pattern_embeddings.json (5.3 MB)
- embedding-tools/attack_pattern_embeddings_qwen4b.json (16.9 MB)
- embedding-tools/cm (0 bytes)

## Deliverables
- [ ] Categorized removal candidate list
- [ ] Justification for each candidate
- [ ] Risk assessment per candidate
EOF
```

**Objective**: Compile comprehensive list of files/modules to remove with justification.

**Removal Criteria:**
1. No imports from active code paths
2. Not called from UI bridge
3. Not imported by any used module
4. Not a test file
5. Not configuration or data file actively used

**Output Format:**
```markdown
## Removal Candidates

### High Confidence (No references found)
- `src/modules/example/unused.py` - No imports, not called
- `embedding-tools/old_script.py` - Superseded by new version

### Medium Confidence (Verify manually)
- `src/modules/utils/helper.py` - Only imported by unused module
- `data/old_embeddings.json` - Not referenced in code

### Low Confidence (Needs investigation)
- `src/modules/core/feature.py` - Unclear if used dynamically
```

**Deliverables:**
- [ ] Categorized removal candidate list
- [ ] Justification for each candidate
- [ ] Risk assessment (High/Medium/Low confidence)

---

#### Task 0.7: Validate Removal Candidates
**Status**: ✅ Complete  
**Priority**: Critical  
**Effort**: 4 hours

**Working Document**: `docs/phase0/task_0.7_validation.md`

**Setup Instructions:**
```bash
cat > docs/phase0/task_0.7_validation.md << 'EOF'
# Task 0.7: Validation Results

**Backlog Reference**: [docs/Backlog.md - Task 0.7](../Backlog.md#task-07-validate-removal-candidates)

## Dynamic Import Check
- [ ] TODO: List files with importlib/exec/eval

## Configuration-Driven Loading
- [ ] TODO: List modules loaded via config

## Runtime Dependency Check
- [ ] TODO: List mode-specific modules

## E2E Test Baseline
```bash
# Run baseline test
python tests/automated_e2e_test.py > baseline_e2e.log 2>&1
```
- [ ] Baseline test exit code: ___
- [ ] Output files generated: ___
- [ ] Execution time: ___

## Documentation Cross-Reference
- [ ] TODO: List modules mentioned in docs

## Deliverables
- [ ] Validated removal list (safe to remove)
- [ ] Flagged items for investigation
- [ ] Baseline E2E test results
EOF
```

**Objective**: Manually verify removal candidates won't break the application.

**Validation Steps:**

1. **Dynamic Import Check**
   - [ ] Search for `importlib.import_module()` calls
   - [ ] Search for `__import__()` calls
   - [ ] Search for `exec()` and `eval()` with module names
   - [ ] Check for string-based class loading

2. **Configuration-Driven Loading**
   - [ ] Review `config.yaml` for module references
   - [ ] Check if any modules are loaded via configuration
   - [ ] Verify plugin/extension mechanisms

3. **Runtime Dependency Check**
   - [ ] Check for modules loaded only in specific modes
   - [ ] Verify CLI-only vs. UI-only modules
   - [ ] Check for conditional imports

4. **E2E Test Validation**
   - [ ] Run `tests/automated_e2e_test.py` before any removals (baseline)
   - [ ] Document which modules are invoked during E2E test
   - [ ] Use E2E test to validate core workflow after each removal phase
   - [ ] Compare E2E test output with expected results
   
   **E2E Test Validation Process:**
   ```bash
   # Baseline test before removals
   cd threatforest-agentic-application/threatforest-strands
   python tests/automated_e2e_test.py > baseline_e2e.log 2>&1
   
   # After each removal phase
   python tests/automated_e2e_test.py > phase_N_e2e.log 2>&1
   diff baseline_e2e.log phase_N_e2e.log
   ```
   
   **E2E Test Success Criteria:**
   - Exit code 0 (success)
   - All output files generated (threat_model.json, attack_trees.json, mitre_mappings.json)
   - No Python import errors
   - No exceptions in traceback
   - Execution completes within reasonable time

5. **Cross-Reference with Documentation**
   - [ ] Check `docs/` for references to modules
   - [ ] Verify README doesn't mention removed features
   - [ ] Update documentation for removed modules

**Deliverables:**
- [ ] Validated removal list (safe to remove)
- [ ] Flagged items requiring further investigation
- [ ] Documentation update requirements
- [ ] Baseline E2E test results

---

#### Task 0.8: Update Documentation and Dependencies
**Status**: ✅ Complete  
**Priority**: Medium  
**Effort**: 2 hours

**Working Document**: `docs/phase0/task_0.8_documentation.md`

**Setup Instructions:**
```bash
cat > docs/phase0/task_0.8_documentation.md << 'EOF'
# Task 0.8: Documentation Updates

**Backlog Reference**: [docs/Backlog.md - Task 0.8](../Backlog.md#task-08-update-documentation-and-dependencies)

## Documentation Files to Update
- [ ] README.md
- [ ] docs/OVERVIEW.md
- [ ] docs/CLI_USAGE.md
- [ ] docs/FOLDER_ORGANIZATION.md
- [ ] docs/UNUSED_MODULES.md (create)

## Dependency Analysis
### Python (requirements.txt)
- [ ] TODO: List unused packages

### Node (ui/package.json)
- [ ] TODO: List unused packages

## Code Comments
- [ ] TODO: List TODO comments for dead code

## Deliverables
- [ ] Updated documentation
- [ ] Unused dependency list
- [ ] Dead code inventory
EOF
```

**Objective**: Update all documentation and dependency files to reflect analysis findings.

**Documentation Updates:**
- [ ] Update `README.md` - Document current architecture
- [ ] Update `docs/OVERVIEW.md` - Update architecture diagrams
- [ ] Update `docs/CLI_USAGE.md` - Document active CLI tools
- [ ] Update `docs/FOLDER_ORGANIZATION.md` - Update structure
- [ ] Create `docs/UNUSED_MODULES.md` - List all identified dead code

**Dependency Analysis:**
- [ ] Review `requirements.txt` - Identify unused Python packages
- [ ] Review `ui/package.json` - Identify unused npm packages
- [ ] Document findings (do not remove yet)

**Code Comments:**
- [ ] Document TODO comments for dead code
- [ ] Add comments marking unused modules

**Deliverables:**
- [ ] Updated documentation reflecting current state
- [ ] List of unused dependencies (for future cleanup)
- [ ] Comprehensive dead code inventory

---

#### Task 0.9: Create Comprehensive Analysis Report
**Status**: ✅ Complete  
**Priority**: High  
**Effort**: 2 hours

**Working Document**: `docs/phase0/task_0.9_analysis_report.md`

**Setup Instructions:**
```bash
cat > docs/phase0/task_0.9_analysis_report.md << 'EOF'
# Task 0.9: Comprehensive Analysis Report

**Backlog Reference**: [docs/Backlog.md - Task 0.9](../Backlog.md#task-09-create-comprehensive-analysis-report)

## Executive Summary
- Total modules analyzed: ___
- Total unused modules: ___
- Total dead code (files): ___
- Storage savings: ~27 MB (embeddings)
- Maintenance reduction: ___

## Analysis Results
- [ ] Module usage matrix (from Task 0.2)
- [ ] Import dependency graph (from Task 0.2)
- [ ] Execution flow diagrams (from Task 0.1)
- [ ] UI component tree (from Task 0.4)

## Removal Candidates
### High Confidence
- [ ] TODO: Copy from task_0.6

### Medium Confidence
- [ ] TODO: Copy from task_0.6

### Low Confidence
- [ ] TODO: Copy from task_0.6

## Risk Assessment
- [ ] TODO: List risky removals

## Recommendations
- [ ] Immediate removal candidates
- [ ] Future cleanup opportunities
- [ ] Technical debt priorities

## Final Report Location
`docs/DEAD_CODE_ANALYSIS_2025-10-22.md`
EOF
```

**Objective**: Document complete analysis findings for decision-making and future reference.

**Report Contents:**
1. **Executive Summary**
   - Total modules analyzed
   - Total unused modules identified
   - Total dead code (lines/files)
   - Estimated storage savings (embedding files)
   - Estimated maintenance burden reduction

2. **Detailed Analysis Results**
   - Complete module usage matrix
   - Import dependency graph
   - Execution flow diagrams
   - UI component tree

3. **Removal Candidates by Category**
   - **High Confidence** (zero references)
   - **Medium Confidence** (only referenced by unused code)
   - **Low Confidence** (needs investigation)
   - **Keep** (actively used)
   - **Keep** (test files)
   - **Keep** (utilities)

4. **Risk Assessment**
   - Modules with dynamic imports
   - Configuration-driven modules
   - Conditional imports
   - Potential breaking changes

5. **Recommendations**
   - Immediate removal candidates
   - Future cleanup opportunities
   - Code organization improvements
   - Technical debt priorities

**Deliverables:**
- [ ] `docs/DEAD_CODE_ANALYSIS_2025-10-22.md`
- [ ] Execution flow diagrams (Mermaid)
- [ ] Module dependency graphs
- [ ] Removal candidate lists with justifications

---

#### Task 0.10: [OPTIONAL] Execute Removal in Phases
**Status**: ✅ Complete  
**Priority**: Optional (After Analysis Complete)  
**Effort**: 4 hours

**Working Document**: `docs/phase0/task_0.10_removal_execution.md`

**Setup Instructions:**
```bash
cat > docs/phase0/task_0.10_removal_execution.md << 'EOF'
# Task 0.10: Removal Execution (OPTIONAL)

**Backlog Reference**: [docs/Backlog.md - Task 0.10](../Backlog.md#task-010-optional-execute-removal-in-phases)

⚠️ **ONLY execute after Tasks 0.1-0.9 complete and analysis approved**

## Prerequisites Checklist
- [ ] Tasks 0.1-0.9 completed
- [ ] Analysis report reviewed
- [ ] Removal candidates validated
- [ ] Baseline E2E test successful
- [ ] Git branch created: `cleanup/phase0-dead-code`

## Phase 1: High Confidence Removals
### Files to Remove
- [ ] TODO: List from task_0.6

### Test Results
- [ ] E2E test exit code: ___
- [ ] UI test: PASS/FAIL
- [ ] Git commit: ___

## Phase 2: Medium Confidence Removals
### Files to Remove
- [ ] TODO: List from task_0.6

### Test Results
- [ ] E2E test exit code: ___
- [ ] UI test: PASS/FAIL
- [ ] Git commit: ___

## Phase 3: Cleanup
### Actions
- [ ] Remove empty directories
- [ ] Update imports
- [ ] Remove unused dependencies

### Test Results
- [ ] E2E test exit code: ___
- [ ] UI test: PASS/FAIL
- [ ] Git commit: ___

## Rollback Log
- [ ] Any rollbacks needed? YES/NO
- [ ] Reason: ___

## Final Summary
- Total files removed: ___
- Total size saved: ___
- Issues encountered: ___
EOF
```

**⚠️ IMPORTANT**: This task should ONLY be executed after Tasks 0.1-0.9 are complete and the analysis report has been reviewed and approved.

**Objective**: Remove dead code in controlled phases with testing between each phase.

**Prerequisites:**
- [ ] Tasks 0.1-0.9 completed
- [ ] Analysis report reviewed and approved
- [ ] Removal candidates validated
- [ ] Baseline E2E test successful
- [ ] Git branch created for cleanup work

**Phase 1: High Confidence Removals**
- [ ] Remove modules with zero references
- [ ] Remove unused embedding files (~27 MB)
- [ ] Remove duplicate/superseded files
- [ ] Git commit: "Phase 1: Remove high confidence dead code"
- [ ] Run full test suite
- [ ] Run E2E test: `python tests/automated_e2e_test.py`
- [ ] Test UI workflow end-to-end
- [ ] Compare results with baseline

**Phase 2: Medium Confidence Removals**
- [ ] Remove modules only referenced by unused code
- [ ] Remove orphaned utilities
- [ ] Git commit: "Phase 2: Remove medium confidence dead code"
- [ ] Run full test suite
- [ ] Run E2E test: `python tests/automated_e2e_test.py`
- [ ] Test UI workflow end-to-end
- [ ] Compare results with baseline

**Phase 3: Cleanup**
- [ ] Remove empty `__init__.py` files in empty directories
- [ ] Remove empty directories
- [ ] Update imports in remaining files
- [ ] Remove unused dependencies from requirements.txt
- [ ] Git commit: "Phase 3: Final cleanup"
- [ ] Run full test suite
- [ ] Run E2E test: `python tests/automated_e2e_test.py`
- [ ] Final UI workflow validation

**Testing Checklist After Each Phase:**

**E2E Test (Headless - Core Workflow):**
- [ ] `python tests/automated_e2e_test.py` exits with code 0
- [ ] Output files generated: threat_model.json, attack_trees.json, mitre_mappings.json
- [ ] No Python import errors in output
- [ ] No exceptions in traceback
- [ ] Execution time within expected range

**UI Test (Full Application):**
- [ ] `python threatforest.py` launches successfully
- [ ] UI loads and displays welcome screen
- [ ] Can select project path
- [ ] Can configure AWS profile and model
- [ ] Can run threat analysis workflow
- [ ] Attack trees are generated
- [ ] TTC mapping works (if enabled)
- [ ] Summary is generated
- [ ] No Python import errors in logs

**Comparison:**
- [ ] E2E test output matches baseline (diff check)
- [ ] UI workflow produces same results as E2E test
- [ ] No new errors introduced

**Rollback Plan:**
- [ ] If any phase fails, revert git commit
- [ ] Document failure reason
- [ ] Re-evaluate removal candidates
- [ ] Update analysis report

**Deliverables:**
- [ ] Git commits for each phase
- [ ] Test results after each phase (E2E + UI)
- [ ] List of files removed in each phase
- [ ] Diff reports comparing baseline to post-removal
- [ ] Final cleanup summary report

---

### Success Criteria for Phase 0

- ✅ Complete execution flow documented from entry points
- ✅ All unused modules identified with high confidence
- ✅ Comprehensive analysis report created
- ✅ Removal candidates validated and categorized
- ✅ Documentation updated to reflect current state
- ✅ Baseline E2E test results captured
- ⚠️ **Optional**: Dead code removed without breaking functionality
- ⚠️ **Optional**: All tests passing after cleanup
- ⚠️ **Optional**: Dependencies cleaned up
- ✅ Removal report created for future reference

---

### Estimated Timeline for Phase 0

- **Week 1**: Tasks 0.1-0.3 (Entry Point & Module Analysis)
- **Week 2**: Tasks 0.4-0.6 (UI & Test Analysis, Candidate List)
- **Week 3**: Tasks 0.7-0.9 (Validation & Analysis Report)
- **Week 4 (Optional)**: Task 0.10 (Execute Removal - if approved)

**Total Analysis Effort**: ~26 hours over 3 weeks  
**Total Removal Effort (Optional)**: +4 hours in week 4

---

### Questions for Clarification

Before proceeding with Phase 0, please confirm:

1. ~~**Embedding Tools**: Should `embedding-tools/` be treated as:~~
   - ~~[ ] Separate utility scripts (keep as-is)~~
   - ~~[ ] Part of main application (analyze for dead code)~~
   - ~~[ ] Development tools only (move to separate repo/archive)~~
   - ✅ **ANSWERED**: Separate utilities - keep all tools, remove unused embedding files only

2. **Archive Directory**: The `archive/` directory contains old code. Should we:
   - [ ] Leave as-is (already archived)
   - [ ] Review for any accidentally archived active code
   - [ ] Remove entirely

3. **Test Files**: Should we:
   - [ ] Keep all test files regardless of coverage
   - [ ] Remove tests for deleted modules
   - [ ] Update tests to reflect removed code

4. **CLI Tools**: Some modules have standalone CLI interfaces (e.g., `ttc_mappings/cli.py`). Should we:
   - [ ] Keep all CLI tools (may be used outside UI)
   - [ ] Remove CLI tools not documented in README
   - [ ] Evaluate each CLI tool individually

5. ~~**Data Files**: For large embedding files (multiple MB), should we:~~
   - ~~[ ] Keep all embedding variants (mpnet, qwen, qwen4b)~~
   - ~~[ ] Keep only the actively used embedding model~~
   - ~~[ ] Move unused embeddings to external storage~~
   - ✅ **ANSWERED**: Keep only qwen model, remove mpnet and qwen4b (~27 MB savings)

---

### Phase 1: Bedrock Model Configuration Centralization

#### Task 1.1: Audit Hardcoded Model IDs
**Status**: ✅ Complete  
**Priority**: High  
**Effort**: 2 hours

**Files with hardcoded models:**
- `src/strands_agent.py` (line 25): `bedrock_model = "us.anthropic.claude-sonnet-4-20250514-v1:0"`
- `src/wizard.py` (lines 454, 459, 464, 469): Model list hardcoded in wizard
- `src/modules/tools/setup_tool.py` (lines 20-25): Model list hardcoded
- `src/modules/tools/information_extraction_tool.py` (lines 1666, 1743): Default model fallback
- `src/modules/tools/context_analysis_tool.py` (line 459): Default model fallback
- `src/modules/tools/ttc_mapping_tool.py` (line 30): Default parameter value

**Action Items:**
- [ ] Create `src/config/models.py` with centralized model definitions
- [ ] Define model categories (fast/balanced/powerful)
- [ ] Add model validation and availability checking
- [ ] Update all files to import from central config

---

#### Task 1.2: Refactor strands_agent.py
**Status**: ✅ Complete  
**Priority**: High  
**Effort**: 1 hour

**Changes Required:**
```python
# Before:
bedrock_model: str = "us.anthropic.claude-sonnet-4-20250514-v1:0"

# After:
from config import Config
bedrock_model: str = Config().get_default_model()
```

**Files to Update:**
- `src/strands_agent.py`

---

#### Task 1.3: Refactor wizard.py Model Selection
**Status**: ✅ Complete  
**Priority**: High  
**Effort**: 2 hours

**Changes Required:**
- Replace hardcoded model list (lines 454-469) with config-based model registry
- Load available models from `Config().get_available_models()`
- Add model metadata (name, description, capabilities)

**Files to Update:**
- `src/wizard.py`

---

#### Task 1.4: Refactor Tool Default Models
**Status**: ✅ Complete  
**Priority**: Medium  
**Effort**: 2 hours

**Changes Required:**
- Update all tool constructors to use `Config().get_default_model()`
- Remove hardcoded fallback values
- Add model parameter validation

**Files to Update:**
- `src/modules/tools/information_extraction_tool.py`
- `src/modules/tools/context_analysis_tool.py`
- `src/modules/tools/ttc_mapping_tool.py`
- `src/modules/tools/setup_tool.py`

---

### Phase 2: Dynamic Region Management

#### Task 2.1: Audit Hardcoded Regions
**Status**: ✅ Complete  
**Priority**: High  
**Effort**: 1 hour

**Files with hardcoded regions:**
- `src/modules/core/bedrock_client.py` (line 26): `region_name = "us-west-2"`
- `src/modules/core/bedrock_service.py` (line 14): `region_name = "us-west-2"`
- `src/wizard.py` (lines 237, 242, 257, 258): `region_name='us-east-1'`
- `src/modules/tools/setup_tool.py` (lines 139, 163): `region_name='us-east-1'`
- `src/modules/tools/information_extraction_tool.py` (lines 128, 996, 1408, 1663, 1740): Multiple `us-east-1` references
- `src/modules/tools/context_analysis_tool.py` (line 456): `region_name='us-east-1'`
- `src/modules/core/bedrock_invoker.py` (lines 93, 109): `region_name='us-east-1'`
- `src/modules/tools/ttc_mapping_tool.py` (lines 231, 384): `region_name='us-east-1'`
- `src/config.py` (line 84): Default fallback to `'us-east-1'`

**Action Items:**
- [ ] Create region resolution utility in `src/modules/core/region_resolver.py`
- [ ] Implement AWS credential chain inspection to extract region
- [ ] Add fallback logic: profile region → env var → config default
- [ ] Update all Bedrock client instantiations

---

#### Task 2.2: Create Region Resolver Utility
**Status**: ✅ Complete  
**Priority**: High  
**Effort**: 3 hours

**Implementation:**
```python
# src/modules/core/region_resolver.py
class RegionResolver:
    """Resolve AWS region from credentials, profile, or config"""
    
    @staticmethod
    def get_region(profile_name: Optional[str] = None) -> str:
        """
        Resolve region in order:
        1. From AWS profile configuration
        2. From AWS_DEFAULT_REGION env var
        3. From application config
        4. Fallback to us-east-1
        """
        pass
```

**Files to Create:**
- `src/modules/core/region_resolver.py`

---

#### Task 2.3: Refactor BedrockClientManager
**Status**: ✅ Complete  
**Priority**: High  
**Effort**: 2 hours

**Changes Required:**
- Update `get_client()` to use `RegionResolver` when `region_name` not provided
- Remove default `region_name` parameters
- Add logging for region resolution

**Files to Update:**
- `src/modules/core/bedrock_client.py`
- `src/modules/core/bedrock_service.py`

---

#### Task 2.4: Update All Bedrock Client Calls
**Status**: ✅ Complete  
**Priority**: High  
**Effort**: 4 hours

**Changes Required:**
- Remove all `region_name='us-east-1'` and `region_name='us-west-2'` hardcoded values
- Let `BedrockClientManager` resolve region automatically
- Update ARN construction to use resolved region

**Files to Update:**
- `src/wizard.py`
- `src/modules/tools/setup_tool.py`
- `src/modules/tools/information_extraction_tool.py`
- `src/modules/tools/context_analysis_tool.py`
- `src/modules/core/bedrock_invoker.py`
- `src/modules/tools/ttc_mapping_tool.py`

---

#### Task 2.5: Update Config Default Region Logic
**Status**: ✅ Complete  
**Priority**: Medium  
**Effort**: 1 hour

**Changes Required:**
- Update `config.py` to use `RegionResolver` for default region
- Document region resolution order in config

**Files to Update:**
- `src/config.py`

---

### Phase 3: Prompt Externalization

#### Task 3.1: Audit Inline Prompts
**Status**: ✅ Complete  
**Priority**: Medium  
**Effort**: 2 hours

**Files with inline prompts:**
- `src/modules/tools/context_analysis_tool.py` (lines 466-479): Context extraction prompt
- `src/modules/tools/attack_tree_generator_tool.py` (line 425): Fallback prompt

**Existing prompt files in `src/prompts/`:**
- ✅ `mitigations.md`
- ✅ `mermaid-prompt.md`
- ✅ `threat-mixed-format.md`
- ✅ `threat-generation-existing.md`
- ✅ `threat-format-fixing.md`
- ✅ `project-analysis.md`
- ✅ `generate-attack-trees.md`
- ✅ `ttc-full-tree-mapping.md`
- ✅ `ttc-attack-step-mapping.md`
- ✅ `threat-generation-new.md`
- ✅ `ttc-mapping.md`

**Action Items:**
- [ ] Create `src/prompts/context-extraction.md` for context analysis
- [ ] Create `src/prompts/attack-tree-fallback.md` for attack tree generation
- [ ] Create prompt loader utility in `src/modules/utils/prompt_loader.py`
- [ ] Update all tools to load prompts from files

---

#### Task 3.2: Create Prompt Loader Utility
**Status**: ✅ Complete  
**Priority**: Medium  
**Effort**: 2 hours

**Implementation:**
```python
# src/modules/utils/prompt_loader.py
class PromptLoader:
    """Load and cache prompts from src/prompts/ directory"""
    
    def __init__(self, prompts_dir: Path = None):
        self.prompts_dir = prompts_dir or Path(__file__).parent.parent / "prompts"
        self._cache = {}
    
    def load(self, prompt_name: str) -> str:
        """Load prompt by name (without .md extension)"""
        pass
    
    def load_with_variables(self, prompt_name: str, **kwargs) -> str:
        """Load prompt and substitute variables"""
        pass
```

**Files to Create:**
- `src/modules/utils/prompt_loader.py`

---

#### Task 3.3: Create Missing Prompt Files
**Status**: ✅ Complete  
**Priority**: Medium  
**Effort**: 1 hour

**Prompts to Create:**

**File**: `src/prompts/context-extraction.md`
```markdown
Analyze the provided files to extract comprehensive application context information. 

Extract and provide:
1. **Application Name**: The name of the system/application
2. **Industry**: Healthcare, Finance, E-commerce, etc.
3. **Architecture Type**: Microservices, Monolithic, Serverless, etc.
4. **Components**: List all system components, services, databases
5. **Technologies**: Programming languages, frameworks, cloud services
6. **Data Flows**: How data moves through the system
7. **Security Controls**: Existing security measures
8. **Deployment Environment**: Cloud provider, regions, etc.
9. **Integration Points**: External systems, APIs, third-party services
10. **Compliance Requirements**: Any regulatory requirements mentioned

Provide a structured JSON response with these fields.
```

**File**: `src/prompts/attack-tree-fallback.md`
```markdown
You are a cybersecurity analyst specializing in threat modeling and attack tree generation. 
Generate Mermaid attack trees from threat statements using proper structure and color coding.
```

**Files to Create:**
- `src/prompts/context-extraction.md`
- `src/prompts/attack-tree-fallback.md`

---

#### Task 3.4: Refactor context_analysis_tool.py
**Status**: ✅ Complete  
**Priority**: Medium  
**Effort**: 1 hour

**Changes Required:**
```python
# Before:
content_parts.append({
    "type": "text",
    "text": """Analyze the provided files..."""
})

# After:
from modules.utils.prompt_loader import PromptLoader
prompt_loader = PromptLoader()
content_parts.append({
    "type": "text",
    "text": prompt_loader.load("context-extraction")
})
```

**Files to Update:**
- `src/modules/tools/context_analysis_tool.py`

---

#### Task 3.5: Refactor attack_tree_generator_tool.py
**Status**: ✅ Complete  
**Priority**: Medium  
**Effort**: 1 hour

**Changes Required:**
- Replace inline fallback prompt with `prompt_loader.load("attack-tree-fallback")`
- Ensure primary prompt loading from file is working correctly

**Files to Update:**
- `src/modules/tools/attack_tree_generator_tool.py`

---

## Testing Requirements

### Test Coverage Needed

#### Unit Tests
- [ ] Test `RegionResolver` with various AWS configurations
- [ ] Test `PromptLoader` with missing files and caching
- [ ] Test model configuration loading and validation
- [ ] Test backward compatibility with existing configurations

#### Integration Tests
- [ ] Test Bedrock client creation with resolved regions
- [ ] Test tool execution with externalized prompts
- [ ] Test wizard flow with config-based models
- [ ] Test cross-region Bedrock operations

#### End-to-End Tests
- [ ] Run full threat modeling workflow with new configuration
- [ ] Verify no hardcoded values remain in execution paths
- [ ] Test with multiple AWS profiles and regions

---

## Migration Plan

### Phase 1: Foundation (Week 1)
1. Create `RegionResolver` utility
2. Create `PromptLoader` utility
3. Create centralized model configuration
4. Write unit tests for new utilities

### Phase 2: Core Refactoring (Week 2)
1. Update `BedrockClientManager` to use `RegionResolver`
2. Update all Bedrock client instantiations
3. Refactor `strands_agent.py` and `wizard.py`
4. Create missing prompt files

### Phase 3: Tool Updates (Week 3)
1. Update all tools to use centralized model config
2. Update all tools to use `PromptLoader`
3. Remove all hardcoded regions from tools
4. Integration testing

### Phase 4: Validation (Week 4)
1. End-to-end testing
2. Documentation updates
3. Code review and cleanup
4. Release notes preparation

---

## Success Criteria

- ✅ Zero hardcoded model IDs in source code
- ✅ Zero hardcoded region names in source code
- ✅ Zero inline prompts in Python files
- ✅ All prompts stored in `src/prompts/` directory
- ✅ Region automatically resolved from AWS credentials
- ✅ Model configuration centralized and maintainable
- ✅ All tests passing
- ✅ Documentation updated

---

## Dependencies

### External Dependencies
- AWS SDK (boto3) for credential/region resolution
- Existing `Config` class in `src/config.py`

### Internal Dependencies
- `BedrockClientManager` refactoring must complete before tool updates
- `PromptLoader` must be created before prompt externalization
- Model config must be created before agent/wizard updates

---

## Risk Assessment

### High Risk
- **Breaking Changes**: Refactoring Bedrock client creation could break existing workflows
  - *Mitigation*: Maintain backward compatibility, extensive testing
  
- **Region Resolution Failures**: Incorrect region detection could cause Bedrock API failures
  - *Mitigation*: Robust fallback logic, clear error messages

### Medium Risk
- **Prompt Loading Failures**: Missing prompt files could cause runtime errors
  - *Mitigation*: Validation at startup, clear error messages
  
- **Configuration Migration**: Existing configs may need updates
  - *Mitigation*: Migration guide, backward compatibility

### Low Risk
- **Performance Impact**: Loading prompts from files vs inline
  - *Mitigation*: Implement caching in `PromptLoader`

---

## Notes

- All changes should maintain backward compatibility where possible
- Configuration changes should be documented in README
- Consider adding configuration validation at application startup
- Add logging for region resolution and model selection for debugging
