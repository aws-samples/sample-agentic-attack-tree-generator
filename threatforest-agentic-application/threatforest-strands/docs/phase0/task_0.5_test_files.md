# Task 0.5: Test Files Identification

**Backlog Reference**: [docs/Backlog.md - Task 0.5](../Backlog.md#task-05-identify-test-files-vs-production-code)

## Objective
Clearly separate test files from production code to avoid accidental removal.

## Test Files to Preserve (DO NOT REMOVE)

### Root Test Files (src/)
1. ✅ **src/test_wizard_ttc.py** - Test for wizard TTC functionality
2. ✅ **src/test_wizard_modes.py** - Test for wizard modes

### Embedding Tools Tests
3. ✅ **embedding-tools/test_matching_improvements.py** - Test for TTC matching improvements

### E2E Tests (tests/)
4. ✅ **tests/automated_e2e_test.py** - End-to-end test (used in Task 0.1)
5. ✅ **tests/automated_e2e_test.sh** - Shell script for E2E test

### Infrastructure Reliability Tests (tests/infrastructure-reliability/)
6. ✅ **test_bedrock_client.py** - Bedrock client tests
7. ✅ **test_enhanced_logging.py** - Logging tests
8. ✅ **test_error_handling.py** - Error handling tests
9. ✅ **test_rate_limiting.py** - Rate limiting tests

### Performance Optimization Tests (tests/performance-optimization/)
10. ✅ **test_bedrock_service.py** - Bedrock service performance tests
11. ✅ **test_cache.py** - Caching tests
12. ✅ **test_file_discovery.py** - File discovery tests

### Strands Production Readiness Tests (tests/strands-production-readiness/)
13. ✅ **test_orchestration_integration.py** - Orchestration integration tests
14. ✅ **test_parallel_execution.py** - Parallel execution tests
15. ✅ **test_pipeline.py** - Pipeline tests
16. ✅ **test_resume_functionality.py** - Resume functionality tests
17. ✅ **test_setup_tool.py** - Setup tool tests
18. ✅ **test_state_cleanup.py** - State cleanup tests
19. ✅ **test_state_context_integration.py** - State context integration tests
20. ✅ **test_state_management.py** - State management tests
21. ✅ **test_strands_integration.py** - Strands integration tests

### Validation & Parsing Tests (tests/validation-parsing/)
22. ✅ **test_parsers.py** - Parser tests
23. ✅ **test_validation.py** - Validation tests

### Test Output Directories (DO NOT REMOVE)
- ✅ **test_outputs/** - Test output directory (root)
- ✅ **tests/test_outputs/** - Test output directory (tests/)
- ✅ **tests/baseline_outputs/** - Baseline test outputs
- ✅ **tests/output/** - Test output directory

## Example/Demo Files (EVALUATE - NOT TESTS)

### TTC Mappings Examples
1. ❓ **src/modules/ttc_mappings/example.py** - Example usage of TTC matching
   - Purpose: Demonstrates how to use TTCMatcher and AttackTreeEnricher
   - Imports: TTCMatcher, AttackTreeEnricher from same module
   - Status: **STANDALONE UTILITY** (identified in Task 0.2)
   - Recommendation: Keep as documentation/example

2. ❓ **src/modules/ttc_mappings/demo_mitigations.py** - Demo of mitigation mapping
   - Purpose: Demonstrates mitigation enrichment
   - Status: **STANDALONE UTILITY** (identified in Task 0.2)
   - Recommendation: Keep as documentation/example

## Summary Statistics

### Test Files: 23
- Root tests: 2
- Embedding tools tests: 1
- E2E tests: 2 (1 Python + 1 Shell)
- Infrastructure tests: 4
- Performance tests: 3
- Production readiness tests: 9
- Validation tests: 2

### Test Directories: 3
- test_outputs/
- tests/test_outputs/
- tests/baseline_outputs/

### Example/Demo Files: 2
- example.py (TTC mappings)
- demo_mitigations.py (TTC mappings)

## Test File Patterns

### Naming Conventions:
- `test_*.py` - Standard test file prefix
- `*_test.py` - Alternative test file suffix
- `automated_e2e_test.*` - E2E test files

### Directory Conventions:
- `tests/` - Main test directory
- `test_outputs/` - Test output directories
- Files in `tests/` subdirectories are all tests

## Preservation Rules

### ALWAYS PRESERVE:
1. Any file starting with `test_`
2. Any file ending with `_test.py`
3. Any file in `tests/` directory
4. Any directory named `test*`
5. Files explicitly identified as tests in this document

### EVALUATE SEPARATELY:
1. Files with `example` in name - may be documentation
2. Files with `demo` in name - may be documentation
3. These are NOT tests but may be useful utilities

## Impact on Removal Tasks

### Files Protected from Removal:
- **23 test files** - Must be preserved
- **3 test directories** - Must be preserved
- **2 example/demo files** - Evaluate separately (not tests)

### Removal Candidates from Previous Tasks:
When removing dead code, ensure none of these test files are affected:
- Task 0.2 identified `example.py` and `demo_mitigations.py` as standalone utilities
- These are NOT tests, but should be evaluated separately
- All actual test files (23 files) must be preserved

## Deliverables
- ✅ Complete list of test files (23 files identified)
- ✅ Complete list of test directories (3 directories)
- ✅ Complete list of example/demo files (2 files - not tests)
- ✅ Clear preservation rules defined

## Recommendations

### For Removal Tasks:
1. **NEVER remove** any file matching test patterns
2. **NEVER remove** any directory in tests/
3. **NEVER remove** test output directories
4. **EVALUATE** example.py and demo_mitigations.py separately (they are utilities, not tests)

### For Documentation:
1. Mark all 23 test files as "PRESERVE" in removal candidate lists
2. Clearly distinguish between tests and examples/demos
3. Update any removal scripts to exclude test patterns

## Notes
- E2E test (automated_e2e_test.py) is actively used in Phase 0 analysis
- All test files should remain even if they test modules that are removed
- Test files help document expected behavior and can be updated later
- Example/demo files serve as documentation and should be kept unless redundant
