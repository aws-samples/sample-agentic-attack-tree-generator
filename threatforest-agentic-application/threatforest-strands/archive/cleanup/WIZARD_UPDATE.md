# Wizard Update - Mitigation Mapping Mode

## ✅ Update Complete

The ThreatForest wizard (`src/wizard.py`) has been updated with a new **Mitigation Mapping** mode.

## New Feature: Option 3 - Mitigation Mapping

### Mode Selection Menu

```
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Option ┃ Mode               ┃ Description                                            ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1      │ Full Analysis      │ Generate attack trees from project (complete workflow) │
│ 2      │ TTC Enrichment     │ Enrich existing attack trees with technique mappings   │
│ 3      │ Mitigation Mapping │ Add mitigations to enriched attack trees               │
└────────┴────────────────────┴────────────────────────────────────────────────────────┘
```

### What It Does

The mitigation mapping mode:
1. Finds enriched attack trees in `output/enriched_v2`
2. Loads the STIX bundle from `stix-data/aaf-bundle.json`
3. Maps techniques to mitigations
4. Injects mitigation nodes into Mermaid diagrams (blue, with 🛡️)
5. Adds mitigation rows to technique tables
6. Saves output to `output/mitigated/`

### Usage

```bash
# Run wizard
python3 src/wizard.py

# Select option 3
Select mode [1]: 3
```

### Output

The wizard will:
- ✅ Process all enriched attack trees
- ✅ Add blue mitigation nodes to diagrams
- ✅ Insert mitigation rows in tables
- ✅ Show summary with statistics
- ✅ Offer to open output directory

### Example Output

```
🎉 Mitigation Mapping Complete!

📊 Results:
• Attack trees processed: 8
• Successfully processed: 8
• Failed: 0
• Techniques with mitigations: 0

📁 Output Directory: output/mitigated

🔍 What was added:
• Blue mitigation nodes in Mermaid diagrams (🛡️)
• Dotted lines connecting attacks to mitigations
• Mitigation rows in technique mapping tables
```

## Files Modified

1. **src/wizard.py**
   - Updated `_select_mode()` to add option 3
   - Updated `_run_wizard()` to handle mitigation mode
   - Added `_run_mitigation_only()` method

## Testing

```bash
# Test the mitigation mode directly
python3 test_mitigation_mode.py
```

## Workflow

```
User runs wizard
    ↓
Selects option 3 (Mitigation Mapping)
    ↓
Wizard finds enriched attack trees
    ↓
Loads STIX bundle
    ↓
Processes each attack tree:
    • Extracts techniques from diagrams
    • Looks up mitigations
    • Injects mitigation nodes
    • Updates technique tables
    ↓
Saves to output/mitigated/
    ↓
Shows summary and offers to open directory
```

## Integration

The wizard now provides a complete workflow:
1. **Option 1**: Full analysis (generate attack trees)
2. **Option 2**: TTC enrichment (add technique mappings)
3. **Option 3**: Mitigation mapping (add mitigations) ⭐ NEW

Each mode can be run independently, allowing users to:
- Run full analysis once
- Re-run enrichment with different settings
- Re-run mitigation mapping with updated STIX bundles
