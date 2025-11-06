# Task 0.6: Removal Candidate List

**Backlog Reference**: [docs/Backlog.md - Task 0.6](../Backlog.md#task-06-create-removal-candidate-list)

## Objective
Compile comprehensive list of files/modules to remove with justification.

## Analysis Summary

Consolidating findings from Tasks 0.1-0.5:
- **Task 0.1**: 13 Python modules called from UI (entry point analysis)
- **Task 0.2**: 40/48 src/ modules used (83% utilization)
- **Task 0.3**: 1 active data file, ~26 MB unused embeddings
- **Task 0.4**: 20/23 UI files used (87% utilization)
- **Task 0.5**: 23 test files protected, 2 example files identified

## Removal Candidates by Confidence Level

---

## HIGH CONFIDENCE - Dead Code (1 file)

### 1. src/threatforest_wizard.py
- **Type**: Python stub file
- **Size**: Minimal
- **Reason**: Empty stub file, no imports, not used anywhere
- **Risk**: None - completely unused
- **Source**: Task 0.2
- **Action**: DELETE

---

## HIGH CONFIDENCE - Unused Embeddings (~26 MB)

### 2. embedding-tools/attack_pattern_embeddings_mpnet.json
- **Type**: Embedding file
- **Size**: 5.0 MB
- **Reason**: mpnet model not used, qwen is active model
- **Risk**: None - different model variant
- **Source**: Task 0.3
- **Action**: DELETE

### 3. embedding-tools/attack_pattern_embeddings.json
- **Type**: Embedding file
- **Size**: 5.0 MB
- **Reason**: Old/duplicate file, qwen version is active
- **Risk**: None - superseded by qwen version
- **Source**: Task 0.3
- **Action**: DELETE

### 4. embedding-tools/attack_pattern_embeddings_qwen4b.json
- **Type**: Embedding file
- **Size**: 16 MB
- **Reason**: qwen4b model not used, qwen is active
- **Risk**: None - different model variant
- **Source**: Task 0.3
- **Action**: DELETE

### 5. embedding-tools/cm
- **Type**: Empty file
- **Size**: 0 bytes
- **Reason**: Empty file, no purpose
- **Risk**: None
- **Source**: Task 0.3
- **Action**: DELETE

**Total Savings: ~26 MB**

---

## HIGH CONFIDENCE - Unused UI Components (3 files)

### 6. ui/src/components/ConfigEditor.tsx
- **Type**: React component
- **Size**: Small
- **Reason**: Not imported anywhere, not part of UI flow
- **Risk**: None - no imports found
- **Source**: Task 0.4
- **Action**: DELETE

### 7. ui/src/components/ThreatSelector.tsx
- **Type**: React component
- **Size**: Small
- **Reason**: Not imported anywhere, not part of UI flow
- **Risk**: None - no imports found
- **Source**: Task 0.4
- **Action**: DELETE

### 8. ui/src/components/FileDiscoveryDisplay.tsx
- **Type**: React component
- **Size**: Small
- **Reason**: Not imported anywhere, not part of UI flow
- **Risk**: None - no imports found
- **Source**: Task 0.4
- **Action**: DELETE

---

## MEDIUM CONFIDENCE - Standalone Utilities (5 files)

These are NOT imported by main application but may be useful as standalone tools.

### 9. src/modules/ttc_mappings/cli.py
- **Type**: Standalone CLI
- **Size**: Small
- **Reason**: Not imported by main app, standalone utility
- **Risk**: Low - may be used independently
- **Source**: Task 0.2
- **Action**: EVALUATE - Keep as utility or remove if redundant

### 10. src/modules/ttc_mappings/mitigation_cli.py
- **Type**: Standalone CLI
- **Size**: Small
- **Reason**: Not imported by main app, standalone utility
- **Risk**: Low - may be used independently
- **Source**: Task 0.2
- **Action**: EVALUATE - Keep as utility or remove if redundant

### 11. src/modules/ttc_mappings/map_mitigations.py
- **Type**: Standalone script
- **Size**: Small
- **Reason**: Not imported by main app, standalone utility
- **Risk**: Low - may be used independently
- **Source**: Task 0.2
- **Action**: EVALUATE - Keep as utility or remove if redundant

### 12. src/modules/ttc_mappings/example.py
- **Type**: Example code
- **Size**: Small
- **Reason**: Example/documentation, not imported by main app
- **Risk**: Low - serves as documentation
- **Source**: Task 0.2, Task 0.5
- **Action**: EVALUATE - Keep as documentation or remove if redundant

### 13. src/modules/ttc_mappings/demo_mitigations.py
- **Type**: Demo code
- **Size**: Small
- **Reason**: Demo/documentation, not imported by main app
- **Risk**: Low - serves as documentation
- **Source**: Task 0.2, Task 0.5
- **Action**: EVALUATE - Keep as documentation or remove if redundant

---

## LOW CONFIDENCE - Needs Investigation (4 items)

### 14. src/modules/tools/threat_jq.sh
- **Type**: Shell script
- **Size**: Small
- **Reason**: Shell script, no Python imports found
- **Risk**: Medium - may be called by subprocess
- **Source**: Task 0.2
- **Action**: INVESTIGATE - Check if called by any tool via subprocess

### 15. src/modules/cli/ (directory)
- **Type**: Empty directory
- **Size**: Minimal
- **Reason**: Contains only empty __init__.py
- **Risk**: None if truly empty
- **Source**: Task 0.2
- **Action**: INVESTIGATE - Verify empty, then remove

### 16. src/wizard.py
- **Type**: Python module
- **Size**: Large (62KB)
- **Reason**: Deprecated CLI interface, only used by test_wizard_modes.py
- **Risk**: Low - E2E test doesn't use it, only unit test depends on it
- **Source**: Task 0.2, Task 0.7
- **Action**: REMOVE - E2E test confirmed independent, test_wizard_modes.py can be updated/removed
- **Updated**: Task 0.7 validation confirmed E2E test bypasses wizard entirely

### 17. embedding-tools/attack_step_matches.json
- **Type**: JSON data file
- **Size**: 135 KB
- **Reason**: Pre-computed matches, unclear if used
- **Risk**: Low - can be regenerated
- **Source**: Task 0.3
- **Action**: INVESTIGATE - Check if used by test scripts

---

## PROTECTED - DO NOT REMOVE

### Test Files (23 files)
All files identified in Task 0.5:
- src/test_wizard_ttc.py
- src/test_wizard_modes.py
- embedding-tools/test_matching_improvements.py
- tests/ directory (20 test files)

### Active Production Code (40 modules)
All modules identified as USED in Task 0.2:
- All 18 core modules
- 6/7 tools (excluding threat_jq.sh pending investigation)
- All 6 parsers
- 5/10 TTC mapping modules (excluding 5 standalone utilities)
- logger.py utility
- strands_agent.py, config.py

### Active UI Components (20 files)
All components identified as USED in Task 0.4:
- 2 entry points
- 15 components
- 2 hooks
- 2 utilities

### Active Data Files (1 file)
- data/embeddings/attack_pattern_embeddings_qwen.json (6.6 MB)

### Embedding Tools (All Python scripts)
All utilities in embedding-tools/ are kept as separate tools:
- cli.py, create_embeddings.py, match_attack_steps.py, etc.

---

## Summary Statistics

### Total Removal Candidates: 17 items

**High Confidence (10 items):**
- 1 dead code file (threatforest_wizard.py)
- 1 deprecated CLI (wizard.py)
- 4 unused embedding files (~26 MB)
- 1 empty file (cm)
- 3 unused UI components

**Medium Confidence (5 items):**
- 5 standalone utilities (keep as separate tools)

**Low Confidence (2 items):**
- 1 empty directory (cli/)
- 1 data file (attack_step_matches.json - can be regenerated)

### Potential Storage Savings
- **Immediate**: ~26 MB (unused embeddings)
- **Additional**: ~135 KB (if attack_step_matches.json removed)
- **Code cleanup**: 10 files + 1 directory (dead code + unused components)

---

## Risk Assessment

### No Risk (10 items):
- threatforest_wizard.py (empty stub)
- wizard.py (deprecated CLI, E2E test independent)
- 4 unused embedding files (different models)
- cm (empty file)
- 3 unused UI components (not imported)

### Low Risk (5 items):
- 5 standalone utilities (not in main flow, may be useful)

### Medium Risk (3 items):
- threat_jq.sh (may be called via subprocess)
- cli/ directory (verify truly empty)
- attack_step_matches.json (may be used by tests)

### High Risk (1 item):
- wizard.py (may be alternate entry point)

---

## Recommended Actions

### Phase 1 - Immediate Removal (No Risk):
1. ✅ DELETE: src/threatforest_wizard.py
2. ✅ DELETE: embedding-tools/attack_pattern_embeddings_mpnet.json
3. ✅ DELETE: embedding-tools/attack_pattern_embeddings.json
4. ✅ DELETE: embedding-tools/attack_pattern_embeddings_qwen4b.json
5. ✅ DELETE: embedding-tools/cm
6. ✅ DELETE: ui/src/components/ConfigEditor.tsx
7. ✅ DELETE: ui/src/components/ThreatSelector.tsx
8. ✅ DELETE: ui/src/components/FileDiscoveryDisplay.tsx

**Impact**: ~26 MB saved, 9 files removed, zero risk

### Phase 2 - After Investigation (Medium/High Risk):
1. ❓ INVESTIGATE: src/modules/tools/threat_jq.sh
2. ❓ INVESTIGATE: src/modules/cli/ directory
3. ❓ INVESTIGATE: src/wizard.py (CRITICAL - may be used)
4. ❓ INVESTIGATE: embedding-tools/attack_step_matches.json

**Action**: Complete Task 0.7 validation before removing

### Phase 3 - Evaluate Utilities (Low Risk):
1. ❓ EVALUATE: Keep or remove 5 standalone TTC utilities
2. ❓ EVALUATE: Keep or remove 2 example/demo files

**Decision**: Based on whether standalone utilities are documented/useful

---

## Deliverables
- ✅ Categorized removal candidate list (17 items)
- ✅ Justification for each candidate
- ✅ Risk assessment per candidate (No/Low/Medium/High)
- ✅ Recommended phased approach
- ✅ Storage savings estimate (~26 MB immediate)

## Next Steps
- Task 0.7: Validate all candidates (especially Medium/High risk items)
- Task 0.7: Investigate wizard.py usage
- Task 0.7: Check threat_jq.sh subprocess calls
- Task 0.7: Verify cli/ directory is empty
- Task 0.7: Check attack_step_matches.json usage in tests
