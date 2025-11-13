# Task 0.3: Data & Embedding Tools Analysis

**Backlog Reference**: [docs/Backlog.md - Task 0.3](../Backlog.md#task-03-analyze-data-and-embedding-tools-usage)

## Confirmed Information
- ✅ Embeddings are pre-computed
- ✅ Active model: qwen (Qwen/Qwen3-Embedding-0.6B)
- ✅ Embedding tools are separate utilities

## Data Directory Analysis

### Current Structure:
```
data/
└── embeddings/
    └── attack_pattern_embeddings_qwen.json (6.6 MB) ✅ ACTIVE
```

### Required Files (Referenced in config.yaml):
- ✅ `data/threat-intelligence/aaf-bundle.json` - **REQUIRED** STIX bundle (1.2 MB)
  - Referenced in: config.yaml, ttc_mappings modules
  - Used by: TTCMatcher.create_embeddings(), MitigationEnricher
  - Status: **FOUND** (added Oct 22, 2025)
  - **Status**: Missing but may be needed for embedding generation

### Configuration (config.yaml):
```yaml
data:
  stix_bundle: "data/threat-intelligence/aaf-bundle.json"  # REQUIRED (1.2 MB)
  embeddings_file: "data/embeddings/attack_pattern_embeddings_qwen.json"  # EXISTS
  
embeddings:
  model: "Qwen/Qwen3-Embedding-0.6B"  # ACTIVE MODEL
```

### Data File Usage:

**attack_pattern_embeddings_qwen.json** (6.6 MB):
- ✅ Referenced in: `config.py` (embeddings_file_path property)
- ✅ Used by: `TTCMatcher` (loaded via config)
- ✅ Status: **ACTIVELY USED**

**aaf-bundle.json** (REQUIRED):
- ✅ Referenced in: `config.py` (stix_bundle_path property)
- ✅ Used by: 
  - `TTCMatcher.create_embeddings()` - for generating embeddings
  - `MitigationEnricher.__init__()` - for loading mitigations
  - `wizard.py` - for TTC enrichment
  - Standalone utilities: cli.py, example.py, demo_mitigations.py, mitigation_cli.py, map_mitigations.py
- ❌ Status: **MISSING - Needed for embedding generation and mitigation mapping**

## Embedding Tools Directory Analysis

### Files in embedding-tools/:

**JSON Files (Embeddings):**
1. ✅ **attack_pattern_embeddings_qwen.json** (6.6 MB) - ACTIVE, copied to data/embeddings/
2. ❌ **attack_pattern_embeddings_mpnet.json** (5.0 MB) - UNUSED model
3. ❌ **attack_pattern_embeddings.json** (5.0 MB) - OLD/duplicate
4. ❌ **attack_pattern_embeddings_qwen4b.json** (16 MB) - UNUSED model
5. ❓ **attack_step_matches.json** (135 KB) - Pre-computed matches?

**Python Scripts (Utilities):**
1. ✅ **cli.py** (13 KB) - Standalone CLI for TTC operations
2. ✅ **create_embeddings.py** (1.6 KB) - Utility to generate embeddings
3. ✅ **match_attack_steps.py** (3.4 KB) - Utility for matching
4. ✅ **match_attack_steps_improved.py** (4.7 KB) - Improved matching utility
5. ✅ **compare_models.py** (4.5 KB) - Model comparison utility
6. ✅ **load_matches.py** (1.3 KB) - Utility to load matches
7. ✅ **test_matching_improvements.py** (8.8 KB) - Test file

**Other Files:**
- ❌ **cm** (0 bytes) - Empty file
- ✅ **README.md**, **QUICK_REFERENCE.md**, etc. - Documentation

**Subdirectories:**
- ✅ **attack-trees/** - Sample attack trees for testing

### Embedding Tools Status:
All Python scripts in embedding-tools/ are **SEPARATE UTILITIES** - not imported by main application.

**Purpose**: Generate embeddings, test matching, compare models - used during development/setup.

## Code References

### config.py:
```python
@property
def embeddings_file_path(self) -> Path:
    return base_path / self.get('data.embeddings_file', 
        'data/embeddings/attack_pattern_embeddings_qwen.json')

@property
def stix_bundle_path(self) -> Path:
    return base_path / self.get('data.stix_bundle', 
        'data/aaf-bundle.json')  # REQUIRED FILE (1.2 MB)

@property
def embeddings_model(self) -> str:
    return self.get('embeddings.model', 'Qwen/Qwen3-Embedding-0.6B')
```

### TTCMatcher (matcher.py):
```python
def __init__(self, embeddings_path: Optional[str] = None, ...):
    if model_name is None:
        from ...config import config
        model_name = config.embeddings_model  # Uses Qwen model
```

### Modules Using STIX Bundle:
1. `wizard.py` - Line 1267: `bundle_path = config.stix_bundle_path`
2. `ttc_mappings/mitigation_enricher.py` - Loads STIX for mitigations
3. `ttc_mappings/cli.py` - CLI for creating embeddings
4. `ttc_mappings/example.py` - Example usage
5. `ttc_mappings/demo_mitigations.py` - Demo script
6. `ttc_mappings/mitigation_cli.py` - Mitigation CLI
7. `ttc_mappings/map_mitigations.py` - Mitigation mapping script

## Removal Candidates

### High Confidence - Unused Embeddings (~27 MB):
1. ❌ **embedding-tools/attack_pattern_embeddings_mpnet.json** (5.0 MB)
   - Reason: mpnet model not used, qwen is active
   
2. ❌ **embedding-tools/attack_pattern_embeddings.json** (5.0 MB)
   - Reason: Old/duplicate file, qwen version is active
   
3. ❌ **embedding-tools/attack_pattern_embeddings_qwen4b.json** (16 MB)
   - Reason: qwen4b model not used, qwen is active
   
4. ❌ **embedding-tools/cm** (0 bytes)
   - Reason: Empty file

**Total Savings: ~26 MB**

### Medium Confidence - Needs Investigation:
1. ❓ **embedding-tools/attack_step_matches.json** (135 KB)
   - May be pre-computed matches for testing
   - Check if used by test scripts

2. ❓ **embedding-tools/attack-trees/** directory
   - Sample attack trees for testing
   - May be used by test scripts

### Keep - Active Files:
1. ✅ **data/embeddings/attack_pattern_embeddings_qwen.json** (6.6 MB)
   - Actively used by TTCMatcher
   
2. ✅ **embedding-tools/attack_pattern_embeddings_qwen.json** (6.6 MB)
   - Source file (duplicate of data/ version)
   - Keep as backup/source

### Keep - Utilities:
All Python scripts in embedding-tools/ are **KEPT** as separate utilities:
- cli.py
- create_embeddings.py
- match_attack_steps.py
- match_attack_steps_improved.py
- compare_models.py
- load_matches.py
- test_matching_improvements.py

### Keep - Documentation:
All .md files in embedding-tools/ are **KEPT**

## Required Data File - RESOLVED ✅

**UPDATE (Oct 22, 2025)**: `data/threat-intelligence/aaf-bundle.json` has been added to the repository.

**File Details**:
- ✅ Location: `data/threat-intelligence/aaf-bundle.json`
- ✅ Size: 1.2 MB
- ✅ Type: STIX bundle for MITRE ATT&CK patterns
- ✅ Purpose: **REQUIRED** for mitigations mapping step

**Referenced in:**
- config.yaml (stix_bundle path)
- 7 Python modules (strands_agent, ttc_mappings utilities)

**Used by:**
- TTCMatcher.create_embeddings() - Generate embeddings from STIX data
- MitigationEnricher - Enrich attack trees with mitigations
- Embedding tools utilities - Create/update embeddings

**Status**: ✅ RESOLVED - File now present and required for full functionality

## Summary

### Data Files:
- ✅ **ACTIVE**: 1 embedding file (attack_pattern_embeddings_qwen.json - 6.6 MB)
- ✅ **REQUIRED**: 1 STIX bundle (aaf-bundle.json - 1.2 MB) - Added Oct 22, 2025

### Embedding Tools:
- ✅ **KEEP**: All Python utilities (separate tools)
- ✅ **KEEP**: All documentation
- ❌ **REMOVE**: 3 unused embedding files (~26 MB)
- ❌ **REMOVE**: 1 empty file (cm)
- ❓ **INVESTIGATE**: attack_step_matches.json, attack-trees/

### Storage Savings:
- Immediate: ~26 MB (unused embeddings)
- Potential: +135 KB (if attack_step_matches.json unused)

## Deliverables
- ✅ List of actively used data files (1 active, 1 missing)
- ✅ Confirmed removal list (~26 MB)
- ✅ Identified missing STIX bundle issue
- ✅ All embedding tools confirmed as separate utilities
