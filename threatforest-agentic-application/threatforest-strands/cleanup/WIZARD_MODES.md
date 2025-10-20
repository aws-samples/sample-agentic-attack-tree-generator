# ThreatForest Wizard - Mode Selection

## Overview

The ThreatForest wizard now supports two modes:
1. **Full Analysis** - Complete workflow from project analysis to attack tree generation
2. **TTC Enrichment** - Enrich existing attack trees with technique mappings

## Mode Selection

When you start the wizard, you'll see:

```
🌳 Welcome to ThreatForest!
...

🎯 Select Mode

┏━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Option ┃ Mode           ┃ Description                                       ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1      │ Full Analysis  │ Generate attack trees from project (complete     │
│        │                │ workflow)                                         │
│ 2      │ TTC Enrichment │ Enrich existing attack trees with technique       │
│        │                │ mappings                                          │
└────────┴────────────────┴───────────────────────────────────────────────────┘

Select mode [1/2] (1):
```

## Mode 1: Full Analysis

**When to use**: First time analyzing a project or generating new attack trees

**What it does**:
1. AWS credentials setup
2. Bedrock model selection
3. Project path selection
4. Threat model document selection
5. Configuration review
6. Full analysis execution:
   - Context analysis
   - Information extraction
   - Attack tree generation
   - Optional TTC enrichment
   - Summary generation

**Output**:
- Attack trees in `output/attack_trees/{project_name}/`
- Optionally enriched trees in `output/attack_trees/{project_name}_enriched/`
- Analysis reports

## Mode 2: TTC Enrichment

**When to use**: After attack trees have been generated, to add technique mappings

**What it does**:
1. Scans `output/attack_trees/` for existing projects
2. Shows available projects with attack tree counts
3. Lets you select which project to enrich
4. Loads TTC matcher with pre-generated embeddings
5. Enriches all attack trees in the selected project
6. Saves enriched versions to `{project_name}_enriched/`

**Example session**:

```
🎯 TTC Enrichment Mode
This mode enriches existing attack trees with TTC technique mappings.

📁 Available Projects:
  1. iot-device-management (4 attack trees)
  2. hcls-example (8 attack trees)

Select project [1/2] (1): 1

✅ Auto-selected: iot-device-management

📄 Found 4 attack trees to enrich
🔧 Loading TTC matcher...
✅ TTC matcher loaded
🎯 Enriching 4 attack trees...
✅ Enrichment complete: 4 successful, 0 failed

🎉 TTC Enrichment Complete!

📊 Results:
• Project: iot-device-management
• Attack trees processed: 4
• Successfully enriched: 4
• Failed: 0

📁 Output Directory: output/attack_trees/iot-device-management_enriched
```

## Workflow Comparison

### Full Analysis Mode
```
Start
  ↓
Welcome
  ↓
Mode Selection → [1] Full Analysis
  ↓
AWS Setup
  ↓
Model Selection
  ↓
Project Path
  ↓
Threat Model
  ↓
Configuration Review
  ↓
Run Analysis
  ├─ Context Analysis
  ├─ Information Extraction
  ├─ Attack Tree Generation
  ├─ Optional TTC Enrichment
  └─ Summary Generation
  ↓
Complete
```

### TTC Enrichment Mode
```
Start
  ↓
Welcome
  ↓
Mode Selection → [2] TTC Enrichment
  ↓
Scan for Projects
  ↓
Select Project
  ↓
Load TTC Matcher
  ↓
Enrich Attack Trees
  ↓
Show Results
  ↓
Complete
```

## Use Cases

### Use Case 1: New Project Analysis
**Mode**: Full Analysis (Option 1)
**Scenario**: First time analyzing a project
**Steps**:
1. Run wizard
2. Select "Full Analysis"
3. Configure AWS and model
4. Point to project directory
5. Generate attack trees
6. Optionally enrich during generation

### Use Case 2: Re-enrich Existing Trees
**Mode**: TTC Enrichment (Option 2)
**Scenario**: Attack trees already generated, want to add/update technique mappings
**Steps**:
1. Run wizard
2. Select "TTC Enrichment"
3. Choose project from list
4. Enrichment runs automatically

### Use Case 3: Batch Enrichment
**Mode**: TTC Enrichment (Option 2)
**Scenario**: Multiple projects need enrichment
**Steps**:
1. Run wizard multiple times
2. Each time select "TTC Enrichment"
3. Select different project each run

## Output Structure

### After Full Analysis
```
output/
├── attack_trees/
│   └── {project_name}/
│       ├── attack_tree_*.md          # Original trees
│       └── ...
└── {project_name}_analysis.md        # Summary report
```

### After TTC Enrichment
```
output/
├── attack_trees/
│   ├── {project_name}/
│   │   ├── attack_tree_*.md          # Original trees
│   │   └── ...
│   └── {project_name}_enriched/
│       ├── enriched_attack_tree_*.md # With TTC mappings
│       └── ...
```

## Benefits of Mode Selection

✅ **Flexibility** - Choose workflow based on needs  
✅ **Efficiency** - Skip full analysis when only enrichment needed  
✅ **Batch processing** - Enrich multiple projects easily  
✅ **No re-analysis** - Reuse existing attack trees  
✅ **Fast** - Enrichment mode completes in seconds  

## Technical Details

### Mode Detection
- Mode selection happens after welcome message
- Choice stored and determines workflow path
- Full analysis: continues with normal wizard flow
- TTC enrichment: skips to enrichment-only method

### Project Discovery
- Scans `output/attack_trees/` directory
- Filters out `*_enriched` directories
- Counts attack tree files in each project
- Shows interactive selection if multiple projects

### Enrichment Process
- Loads pre-generated embeddings (6.6MB)
- Processes each attack tree file
- Adds technique IDs to mermaid diagrams
- Creates technique mapping tables
- Saves to separate enriched directory

## Troubleshooting

### "No project directories found"
**Problem**: No attack trees exist yet  
**Solution**: Run Full Analysis mode first to generate attack trees

### "Embeddings file not found"
**Problem**: Missing TTC embeddings  
**Solution**: 
```bash
cd src
python -m modules.ttc_mappings.cli create \
    ../stix-data/aaf-bundle.json \
    -o modules/ttc_mappings/data/ttc_embeddings.json
```

### "No attack tree files found"
**Problem**: Project directory exists but no attack trees  
**Solution**: Check if files match pattern `attack_tree_*.md`

## Command Line Testing

Test mode selection:
```bash
cd src
python test_wizard_modes.py
```

Run wizard:
```bash
cd src
python threatforest_wizard.py
```

## Related Documentation

- **TTC Enrichment Guide**: `WIZARD_TTC_ENRICHMENT.md`
- **Integration Summary**: `WIZARD_INTEGRATION_SUMMARY.md`
- **Module README**: `src/modules/ttc_mappings/README.md`
