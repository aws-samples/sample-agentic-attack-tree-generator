# ThreatComposer File Handling Improvements

## Current Issues

### 1. Missing Threat Details in Attack Tree Markdown Files
**Problem**: Attack tree markdown files for ThreatComposer threats show:
- `**Associated threat statement**: None`
- Missing structured threat details (Threat Source, Prerequisites, Threat Action, etc.)

**Example from genai-chatbot output**:
```markdown
# Attack Tree: LLM07 System Prompt Leakage
**Threat ID**: 04330dd9-b830-45ae-8dcb-6149919ea8f0  
**Associated threat statement**: None
```

**Expected format (from iot-device-management)**:
```markdown
# Attack Tree: Authentication
**Threat ID**: T001  
**Associated threat statement**: A malicious attacker with compromised X.509 certificates...

- **Threat Source**: malicious attacker
- **Prerequisites**: compromised X.509 certificates
- **Threat Action**: impersonate legitimate IoT devices
- **Threat Impact**: injection of malicious sensor data
- **Reduced Goal**: integrity
- **Impacted Assets**: device data and control systems
- **Priority**: High
- **Category**: Authentication
```

### 2. Threat ID Format Inconsistency
**Problem**: ThreatComposer uses UUIDs as threat IDs instead of sequential format (T001, T002, etc.)
- Makes filenames long and hard to read
- Inconsistent with markdown-based threat files

**Current**: `04330dd9-b830-45ae-8dcb-6149919ea8f0`
**Expected**: `T001`, `T002`, etc.

### 3. Incomplete Threat Data Structure
**Problem**: ThreatComposer parser creates threats with minimal fields:
```json
{
  "id": "uuid",
  "statement": "...",
  "severity": "High",
  "priority": "High",
  "category": "LLM07 System Prompt Leakage",
  "source": "threatcomposer"
}
```

**Missing fields needed for attack tree generation**:
- `description` (full detailed breakdown)
- `threatSource`
- `prerequisites`
- `threatAction`
- `threatImpact`
- `impactedGoal`
- `impactedAssets`

### 4. Category Field Usage
**Problem**: Using `tags` array as category creates long category names
- Example: "LLM07 System Prompt Leakage" instead of just "System Prompt Leakage"
- Should extract cleaner category names

---

## Proposed Solutions

### Task 1: Enhance ThreatComposer Parser Data Structure
**File**: `src/modules/tools/information_extraction_tool.py` (lines 285-315)

**Changes**:
1. Extract priority from metadata array (ThreatComposer-specific):
   ```python
   # ONLY for threatcomposer format - extract priority from metadata
   if parsed_data.get('format') == 'threatcomposer':
       for threat in parsed_data.get('threats', []):
           # Extract priority from metadata array
           priority = 'Medium'  # Default
           for meta in threat.get('metadata', []):
               if meta.get('key') == 'Priority':
                   priority = meta.get('value', 'Medium')
                   break
           
           # Build statement if not present
           statement = threat.get('statement', '')
           if not statement:
               # Build from components
               ...
   ```

2. Map all ThreatComposer fields properly:
   ```python
   threats.append({
       'id': threat.get('id'),  # Keep UUID for now
       'numericId': threat.get('numericId'),  # For potential T001 format
       'statement': statement,  # Full statement
       'threatSource': threat.get('threatSource', ''),
       'prerequisites': threat.get('prerequisites', ''),
       'threatAction': threat.get('threatAction', ''),
       'threatImpact': threat.get('threatImpact', ''),
       'impactedGoal': threat.get('impactedGoal', []),
       'impactedAssets': threat.get('impactedAssets', []),
       'severity': priority,  # Mapped from metadata Priority
       'priority': priority,  # Mapped from metadata Priority
       'category': ', '.join(threat.get('tags', [])),  # Use tags as-is
       'source': 'threatcomposer',
       'source_file': file_path
   })
   ```

3. Category extraction:
   - Use tags array directly without modification
   - Join multiple tags with comma if present
   - Example: "LLM07 System Prompt Leakage" stays as "LLM07 System Prompt Leakage"

**Important**: This priority mapping logic is ONLY applied when `parsed_data.get('format') == 'threatcomposer'`. Other parsers (markdown, JSON, YAML) use their existing priority/severity extraction logic and are not affected.

**Estimated effort**: 30 minutes

---

### Task 2: Add Threat ID Conversion Option
**File**: `src/modules/tools/information_extraction_tool.py`

**Changes**:
1. Add option to convert UUID to sequential format:
   ```python
   # Option 1: Use numericId if available
   threat_id = f"T{threat.get('numericId', idx):03d}"
   
   # Option 2: Keep UUID but add sequential as secondary
   threat_id = threat.get('id')
   sequential_id = f"T{idx:03d}"
   ```

2. Store both IDs:
   ```python
   'id': threat_id,  # T001 format
   'uuid': threat.get('id'),  # Original UUID
   'numericId': threat.get('numericId')
   ```

**Decision needed**: 
- Use sequential IDs (T001) for consistency?
- Keep UUIDs for traceability back to ThreatComposer?
- Use both (sequential as primary, UUID as reference)?

**Estimated effort**: 20 minutes

---

### Task 3: Update Attack Tree Markdown Generator
**File**: `src/modules/tools/summary_generator_tool.py` (lines 48-70)

**Current Issue**: Attack tree markdown shows `**Associated threat statement**: None` because it's looking for `threat_description` which is null, instead of using `threat_statement` which contains the full statement.

**Changes**:
1. Fix statement extraction to use correct field:
   ```python
   # Get the full threat statement (already populated correctly in attack tree data)
   statement = tree.get('threat_statement', tree.get('statement', ''))
   # Don't use threat_description - it's None for ThreatComposer
   ```

2. Build full threat description with all fields:
   ```python
   # Extract threat details
   threat_source = tree.get('threatSource', '')
   prerequisites = tree.get('prerequisites', '')
   threat_action = tree.get('threatAction', '')
   threat_impact = tree.get('threatImpact', '')
   impacted_goal = tree.get('impactedGoal', [])
   impacted_assets = tree.get('impactedAssets', [])
   
   # Build detailed section
   details = f"""**Associated threat statement**: {statement}

   - **Threat Source**: {threat_source}
   - **Prerequisites**: {prerequisites}
   - **Threat Action**: {threat_action}
   - **Threat Impact**: {threat_impact}
   - **Reduced Goal**: {', '.join(impacted_goal) if isinstance(impacted_goal, list) else impacted_goal}
   - **Impacted Assets**: {', '.join(impacted_assets) if isinstance(impacted_assets, list) else impacted_assets}
   - **Priority**: {tree.get('priority', 'Unknown')}
   - **Category**: {category_name}
   """
   ```

3. Update file content template to include all details in the header section

**Note**: The `threat_statement` field is already correctly populated with the full ThreatComposer statement. This task just fixes the markdown generator to use it.

**Estimated effort**: 30 minutes

---

### Task 4: Standardize Threat Data Flow
**Files**: Multiple

**Changes**:
1. Ensure consistent field names across:
   - Parser output
   - Information extraction tool
   - Attack tree generator input
   - Summary generator output

2. Create a standard threat schema:
   ```python
   THREAT_SCHEMA = {
       'id': str,  # T001 or UUID
       'statement': str,  # Full threat statement
       'description': str,  # Same as statement or detailed breakdown
       'threatSource': str,
       'prerequisites': str,
       'threatAction': str,
       'threatImpact': str,
       'impactedGoal': list or str,
       'impactedAssets': list or str,
       'severity': str,  # High/Medium/Low
       'priority': str,  # High/Medium/Low
       'category': str,
       'source': str,  # threatcomposer/markdown/json
       'source_file': str
   }
   ```

**Estimated effort**: 45 minutes

---

### Task 5: Update Attack Tree Generator to Handle Both Formats
**File**: `src/modules/tools/attack_tree_generator_tool.py`

**Changes**:
1. Accept threats with either format (UUID or T001)
2. Handle missing fields gracefully
3. Build complete threat context for LLM prompt:
   ```python
   threat_context = f"""
   Threat: {threat.get('statement')}
   Source: {threat.get('threatSource', 'Unknown')}
   Prerequisites: {threat.get('prerequisites', 'None specified')}
   Action: {threat.get('threatAction', 'Unknown')}
   Impact: {threat.get('threatImpact', 'Unknown')}
   """
   ```

**Estimated effort**: 30 minutes

---

## Implementation Priority

### Phase 1: Critical (Fixes immediate issues)
1. **Task 1**: Enhance ThreatComposer Parser Data Structure
2. **Task 3**: Update Attack Tree Markdown Generator

**Result**: Attack tree markdown files will have complete threat details

### Phase 2: Standardization
3. **Task 4**: Standardize Threat Data Flow
4. **Task 5**: Update Attack Tree Generator

**Result**: Consistent data structure across all parsers

### Phase 3: Enhancement (Optional)
5. **Task 2**: Add Threat ID Conversion Option

**Result**: Cleaner threat IDs and filenames

---

## Testing Plan

### Test Case 1: ThreatComposer File with High Priority Threats
**Input**: `ThreatComposer_Workspace_GenAI-Chatbot.tc.json`
**Expected**:
- 17 High priority threats identified
- Attack tree markdown files contain full threat details
- All structured fields populated

### Test Case 2: Markdown Threat File (Regression)
**Input**: IoT Device Management markdown files
**Expected**:
- No regression in existing functionality
- Same output format maintained

### Test Case 3: Mixed Sources
**Input**: Project with both ThreatComposer and markdown files
**Expected**:
- Both formats parsed correctly
- Consistent output structure

---

## Questions for Review

1. **Threat ID Format**: Should we convert UUIDs to T001 format, or keep both?
   - **Recommendation**: Use T001 format for consistency, store UUID as reference

2. **Category Cleaning**: Should we strip "LLM##" prefixes from categories?
   - **Recommendation**: Yes, cleaner and more readable

3. **Backward Compatibility**: Should we maintain support for old format?
   - **Recommendation**: Yes, add migration path

4. **Field Mapping**: Any additional ThreatComposer fields we should capture?
   - Check: `displayOrder`, `tags`, `metadata` array

---

## Estimated Total Effort
- Phase 1: 1 hour
- Phase 2: 1.25 hours  
- Phase 3: 20 minutes
- Testing: 30 minutes

**Total**: ~3 hours

---

## Success Criteria

✅ Attack tree markdown files from ThreatComposer show complete threat details
✅ Threat IDs are consistent and readable
✅ All threat fields properly mapped and accessible
✅ No regression in markdown file parsing
✅ Clean, maintainable code structure
