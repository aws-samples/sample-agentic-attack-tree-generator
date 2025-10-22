# Task 0.10: Removal Execution (OPTIONAL)

**Backlog Reference**: [docs/Backlog.md - Task 0.10](../Backlog.md#task-010-optional-execute-removal-in-phases)

⚠️ **ONLY execute after Tasks 0.1-0.9 complete and analysis approved**

---

## Prerequisites Checklist

- ✅ Tasks 0.1-0.9 completed
- ✅ Analysis report reviewed ([task_0.9_analysis_report.md](task_0.9_analysis_report.md))
- ✅ Removal candidates validated
- [ ] Baseline E2E test successful
- [ ] Git branch created: `cleanup/phase0-dead-code`
- [ ] Approval obtained to proceed

---

## Removal Plan

### Phase 1: High Confidence Removals (12 items)

**Files to Remove:**

**Python (3):**
1. src/threatforest_wizard.py
2. src/wizard.py
3. src/modules/cli/__init__.py

**Embeddings (5):**
4. embedding-tools/attack_pattern_embeddings_mpnet.json
5. embedding-tools/attack_pattern_embeddings.json
6. embedding-tools/attack_pattern_embeddings_qwen4b.json
7. embedding-tools/attack_step_matches.json
8. embedding-tools/cm

**UI Components (3):**
9. ui/src/components/ConfigEditor.tsx
10. ui/src/components/ThreatSelector.tsx
11. ui/src/components/FileDiscoveryDisplay.tsx

**Directories (1):**
12. src/modules/cli/ (after __init__.py removed)

**Commands:**
```bash
# Create branch
git checkout -b cleanup/phase0-dead-code

# Remove Python files
rm src/threatforest_wizard.py
rm src/wizard.py
rm -rf src/modules/cli/

# Remove embedding files
rm embedding-tools/attack_pattern_embeddings_mpnet.json
rm embedding-tools/attack_pattern_embeddings.json
rm embedding-tools/attack_pattern_embeddings_qwen4b.json
rm embedding-tools/attack_step_matches.json
rm embedding-tools/cm

# Remove UI components
rm ui/src/components/ConfigEditor.tsx
rm ui/src/components/ThreatSelector.tsx
rm ui/src/components/FileDiscoveryDisplay.tsx

# Commit
git add -A
git commit -m "Phase 0: Remove dead code (12 items, ~26.1 MB savings)

- Remove deprecated CLI files (wizard.py, threatforest_wizard.py)
- Remove unused embedding files (mpnet, qwen4b variants)
- Remove unused UI components (ConfigEditor, ThreatSelector, FileDiscoveryDisplay)
- Remove empty cli/ directory"
```

---

## Testing Checklist

### Before Removal
- [ ] Run E2E test: `python tests/automated_e2e_test.py`
- [ ] Record exit code: ___
- [ ] Record output files: ___
- [ ] Test UI: `python threatforest.py`
- [ ] Verify UI loads and works

### After Removal
- [ ] Run E2E test: `python tests/automated_e2e_test.py`
- [ ] Exit code: ___ (should be 0)
- [ ] Output files match baseline: ___
- [ ] Test UI: `python threatforest.py`
- [ ] Verify UI loads and works
- [ ] No import errors in logs
- [ ] All workflows complete successfully

---

## Test Results

### Baseline (Before Removal)
```
Date: ___________
E2E Test Exit Code: ___
Output Files: ___
UI Test: PASS/FAIL
Notes: ___
```

### Phase 1 (After Removal)
```
Date: ___________
E2E Test Exit Code: ___
Output Files: ___
UI Test: PASS/FAIL
Diff from Baseline: ___
Issues Found: ___
```

---

## Rollback Plan

**If any issues occur:**

```bash
# Rollback commit
git reset --hard HEAD~1

# Or revert specific commit
git revert <commit-hash>

# Document reason
echo "Rollback reason: ___" >> rollback.log
```

---

## Cleanup Actions

### After Successful Removal

1. **Update imports** (if needed)
   - [ ] Check for any broken imports
   - [ ] Update any references

2. **Remove empty directories**
   - [ ] Check for empty __pycache__ directories
   - [ ] Remove if found

3. **Final commit**
   ```bash
   git add -A
   git commit -m "Phase 0: Final cleanup"
   ```

---

## Final Summary

### Execution Results

**Files Removed**: ___/12  
**Storage Saved**: ___ MB  
**Issues Encountered**: ___  
**Rollbacks Needed**: YES/NO  
**Final Status**: SUCCESS/FAILED

**Note**: test_wizard_modes.py can also be removed (tests deprecated wizard.py)  

### Test Results Summary

**E2E Test**: PASS/FAIL  
**UI Test**: PASS/FAIL  
**Import Errors**: YES/NO  
**Functional Issues**: YES/NO  

---

## Deliverables

- [ ] Git commit with removals
- [ ] Test results documented
- [ ] Diff report (baseline vs post-removal)
- [ ] Issues log (if any)
- [ ] Final summary report

---

## Status

**Execution Status**: ⏳ Not Started

**Approval**: ⏳ Pending

**Next Steps**: 
1. Obtain approval to proceed
2. Create git branch
3. Run baseline tests
4. Execute removal
5. Run post-removal tests
6. Document results

---

**Note**: This task is OPTIONAL. Analysis is complete and can be archived without executing removal.
