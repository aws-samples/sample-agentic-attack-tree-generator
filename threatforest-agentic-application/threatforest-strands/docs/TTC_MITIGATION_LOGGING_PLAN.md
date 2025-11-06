# TTC Mapping & Mitigation Logging Enhancement Plan

**Date**: October 23, 2025  
**Objective**: Add verbose, user-friendly logging to TTC mapping and mitigation phases to match the verbosity of context analysis and attack tree generation phases.

---

## Current State

The TTC mapping and mitigation phases have minimal logging compared to earlier phases. Users see limited feedback during these potentially long-running operations.

**Current logging examples:**
- `self.logger.info(f"Using Bedrock-only MITRE ATT&CK mapping (no local STIX data)")`
- Basic error logging only

**Desired logging examples (from other tools):**
- `"Discovered {discovered.total_files} files in {discovered.discovery_time_ms:.2f}ms"`
- `"Analyzing {len(files_to_analyze)} files via Bedrock for enhanced context"`
- `"✓ Generated attack tree for threat: {threat_id}"`

---

## Phase 1: TTC Mapping (ttc_mapping_tool.py)

### Main Activities & Logging Points

#### 1. **Initialization & Data Loading**
**Location**: `execute()` method, lines ~27-50

**Activities:**
- Loading STIX bundle data
- Extracting techniques from STIX
- Determining mapping strategy (Bedrock-only vs. hybrid)

**Logging to add:**
```python
# At start of execute()
self.logger.info(f"🎯 Starting TTC mapping for {len(attack_trees.get('attack_trees', []))} attack trees")

# After loading STIX data
if stix_data:
    self.logger.info(f"📚 Loaded STIX bundle with {len(stix_data.get('objects', []))} objects")
else:
    self.logger.warning("⚠️  No STIX data found, using Bedrock-only mapping")

# After extracting techniques
self.logger.info(f"🔍 Extracted {len(techniques)} TTC techniques from STIX data")
```

#### 2. **Per-Tree Processing**
**Location**: Loop through attack trees in `execute()`

**Activities:**
- Processing each attack tree individually
- Extracting attack steps from tree
- Preparing for mapping

**Logging to add:**
```python
# Before processing each tree
self.logger.info(f"📊 Processing attack tree {idx + 1} of {total_trees}: {tree.get('threat_id', 'unknown')}")

# After extracting steps
self.logger.info(f"   └─ Extracted {len(attack_steps)} attack steps for mapping")
```

#### 3. **Bedrock Mapping Execution**
**Location**: `_bedrock_map_batch()` method, line ~214

**Activities:**
- Batching attack steps
- Calling Bedrock for TTC mapping
- Parsing Bedrock responses

**Logging to add:**
```python
# Before Bedrock call
self.logger.info(f"🤖 Mapping {len(attack_steps)} attack steps via Bedrock...")

# After successful mapping
self.logger.info(f"✓ Successfully mapped {successful_count} of {len(attack_steps)} attack steps")

# If using fallback
self.logger.warning(f"⚠️  Using keyword fallback for {fallback_count} unmapped steps")
```

#### 4. **Candidate Technique Selection**
**Location**: `_get_candidate_techniques()` method, line ~189

**Activities:**
- Filtering techniques by keywords
- Selecting top candidates

**Logging to add:**
```python
# After filtering
self.logger.debug(f"   └─ Found {len(candidates)} candidate techniques for step: '{step_text[:50]}...'")
```

#### 5. **Mapping Results**
**Location**: End of `execute()` method

**Activities:**
- Aggregating mapping statistics
- Preparing final results

**Logging to add:**
```python
# Final summary
total_mappings = sum(len(tree.get('ttc_mappings', [])) for tree in enriched_trees)
self.logger.info(f"✅ TTC Mapping Complete:")
self.logger.info(f"   ├─ Total trees processed: {len(enriched_trees)}")
self.logger.info(f"   ├─ Total mappings created: {total_mappings}")
self.logger.info(f"   ├─ Average mappings per tree: {total_mappings / len(enriched_trees):.1f}")
self.logger.info(f"   └─ Threshold used: {self.threshold}")
```

---

## Phase 2: Attack Tree Enrichment (enricher.py)

### Main Activities & Logging Points

#### 1. **Attack Step Extraction**
**Location**: `extract_attack_steps()` method, line ~18

**Activities:**
- Parsing mermaid diagram
- Extracting attack step text

**Logging to add:**
```python
# After extraction
self.logger.info(f"📝 Extracted {len(steps)} unique attack steps from mermaid diagram")
```

#### 2. **Technique Matching**
**Location**: `enrich_attack_tree()` method, line ~75

**Activities:**
- Matching steps to techniques
- Calculating similarity scores

**Logging to add:**
```python
# Before matching
self.logger.info(f"🔗 Matching {len(steps)} attack steps to TTC techniques...")

# After matching
matched_count = sum(1 for m in matches if m['matches'])
self.logger.info(f"✓ Matched {matched_count} of {len(steps)} steps to techniques")
```

#### 3. **Diagram Enrichment**
**Location**: `enrich_mermaid_diagram()` method, line ~33

**Activities:**
- Adding technique IDs to diagram nodes
- Creating technique mapping table

**Logging to add:**
```python
# After enrichment
self.logger.info(f"📊 Enriched mermaid diagram with {len(step_to_technique)} technique annotations")
```

---

## Phase 3: Mitigation Enrichment (mitigation_enricher.py)

### Main Activities & Logging Points

#### 1. **STIX Data Loading**
**Location**: `_load_stix_data()` method, line ~23

**Activities:**
- Loading STIX bundle
- Indexing attack patterns and mitigations
- Building mitigation relationships

**Logging to add:**
```python
# After loading bundle
self.logger.info(f"📚 Loaded STIX bundle from {self.stix_bundle_path}")
self.logger.info(f"   ├─ Attack patterns: {len(self.attack_patterns)}")
self.logger.info(f"   ├─ Mitigations: {len(self.mitigations)}")
self.logger.info(f"   └─ Mitigation relationships: {len(self.mitigation_map)}")
```

#### 2. **Technique Mitigation Lookup**
**Location**: `get_mitigations_for_technique()` method, line ~48

**Activities:**
- Finding attack pattern for technique
- Retrieving associated mitigations

**Logging to add:**
```python
# When mitigations found
if mitigations:
    self.logger.debug(f"   └─ Found {len(mitigations)} mitigations for technique {technique_id}")
else:
    self.logger.debug(f"   └─ No mitigations found for technique {technique_id}")
```

#### 3. **Attack Tree Enrichment**
**Location**: `enrich_attack_tree()` method, line ~63

**Activities:**
- Processing each node in attack tree
- Adding mitigation information
- Creating mitigation sections

**Logging to add:**
```python
# Before enrichment
self.logger.info(f"🛡️  Enriching attack tree with mitigations...")

# After processing nodes
total_mitigations = sum(len(node.get('mitigations', [])) for node in enriched['nodes'])
self.logger.info(f"✓ Added {total_mitigations} mitigations across {len(enriched['nodes'])} nodes")
```

#### 4. **Markdown Generation**
**Location**: `enrich_markdown()` method (if exists)

**Activities:**
- Generating mitigation markdown sections
- Formatting mitigation details

**Logging to add:**
```python
# After markdown generation
self.logger.info(f"📄 Generated mitigation documentation with {mitigation_count} entries")
```

---

## Phase 4: Mitigation Mapping (mitigation_mapper.py)

### Main Activities & Logging Points

#### 1. **Bundle Loading**
**Location**: `_load_bundle()` method, line ~14

**Activities:**
- Loading STIX bundle
- Building technique-to-mitigation index

**Logging to add:**
```python
# After loading
self.logger.info(f"📚 Loaded mitigation mappings from bundle")
self.logger.info(f"   └─ Techniques with mitigations: {len(self.technique_to_mitigations)}")
```

#### 2. **Technique Extraction from Trees**
**Location**: `extract_techniques_from_tree()` method

**Activities:**
- Parsing enriched attack trees
- Extracting technique IDs

**Logging to add:**
```python
# After extraction
self.logger.info(f"🔍 Extracted {len(techniques)} unique techniques from attack tree")
```

#### 3. **Mitigation Mapping**
**Location**: `map_techniques_to_mitigations()` method

**Activities:**
- Mapping each technique to mitigations
- Aggregating results

**Logging to add:**
```python
# Before mapping
self.logger.info(f"🔗 Mapping {len(techniques)} techniques to mitigations...")

# After mapping
mapped_count = sum(1 for t in results if results[t])
self.logger.info(f"✓ Found mitigations for {mapped_count} of {len(techniques)} techniques")
```

---

## Implementation Priority

### High Priority (User-Facing)
1. **TTC Mapping Tool** - Main workflow logging (Phase 1, items 1-3, 5)
2. **Mitigation Enricher** - STIX loading and enrichment (Phase 3, items 1, 3)

### Medium Priority (Progress Tracking)
3. **Attack Tree Enricher** - Matching and enrichment (Phase 2, items 2-3)
4. **Mitigation Mapper** - Mapping workflow (Phase 4, items 2-3)

### Low Priority (Debug)
5. **All Debug Logging** - Detailed per-step information

---

## Logging Style Guide

### Emojis for Visual Clarity
- 🎯 Starting/Initializing
- 📚 Loading data
- 🔍 Searching/Extracting
- 📊 Processing/Analyzing
- 🤖 AI/Bedrock operations
- 🔗 Matching/Mapping
- ✓ Success
- ⚠️  Warning/Fallback
- ❌ Error
- 🛡️  Security/Mitigation
- 📝 Writing/Creating
- 📄 Documentation

### Message Format
```python
# High-level operations
self.logger.info(f"🎯 Starting operation...")

# Sub-operations with tree structure
self.logger.info(f"   ├─ Sub-operation 1: {detail}")
self.logger.info(f"   ├─ Sub-operation 2: {detail}")
self.logger.info(f"   └─ Sub-operation 3: {detail}")

# Completion
self.logger.info(f"✅ Operation Complete:")
self.logger.info(f"   ├─ Metric 1: {value}")
self.logger.info(f"   └─ Metric 2: {value}")
```

### Verbosity Levels
- **INFO**: User-facing progress and results
- **DEBUG**: Detailed per-item processing
- **WARNING**: Fallbacks and non-critical issues
- **ERROR**: Failures requiring attention

---

## Testing Checklist

After implementation, verify:
- [ ] Log messages appear in centralized log file
- [ ] Progress is visible during long operations
- [ ] Success/failure states are clear
- [ ] Statistics are accurate and helpful
- [ ] Emoji rendering works in terminal
- [ ] Tree structure formatting is correct
- [ ] No performance impact from logging
- [ ] Debug logs can be filtered out

---

## Example Output (Target)

```
2025-10-23 12:00:00 - ThreatForest.TTCMappingTool - INFO - 🎯 Starting TTC mapping for 4 attack trees
2025-10-23 12:00:01 - ThreatForest.TTCMappingTool - INFO - 📚 Loaded STIX bundle with 1,247 objects
2025-10-23 12:00:01 - ThreatForest.TTCMappingTool - INFO - 🔍 Extracted 342 TTC techniques from STIX data
2025-10-23 12:00:02 - ThreatForest.TTCMappingTool - INFO - 📊 Processing attack tree 1 of 4: T001_authentication
2025-10-23 12:00:02 - ThreatForest.TTCMappingTool - INFO -    └─ Extracted 12 attack steps for mapping
2025-10-23 12:00:03 - ThreatForest.TTCMappingTool - INFO - 🤖 Mapping 12 attack steps via Bedrock...
2025-10-23 12:00:08 - ThreatForest.TTCMappingTool - INFO - ✓ Successfully mapped 11 of 12 attack steps
2025-10-23 12:00:08 - ThreatForest.TTCMappingTool - INFO - ⚠️  Using keyword fallback for 1 unmapped step
...
2025-10-23 12:00:45 - ThreatForest.TTCMappingTool - INFO - ✅ TTC Mapping Complete:
2025-10-23 12:00:45 - ThreatForest.TTCMappingTool - INFO -    ├─ Total trees processed: 4
2025-10-23 12:00:45 - ThreatForest.TTCMappingTool - INFO -    ├─ Total mappings created: 47
2025-10-23 12:00:45 - ThreatForest.TTCMappingTool - INFO -    ├─ Average mappings per tree: 11.8
2025-10-23 12:00:45 - ThreatForest.TTCMappingTool - INFO -    └─ Threshold used: 0.8
```
