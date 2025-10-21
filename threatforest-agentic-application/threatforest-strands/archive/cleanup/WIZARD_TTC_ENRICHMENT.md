# ThreatForest Wizard - TTC Enrichment Feature

## Overview

The ThreatForest wizard now includes an optional TTC (Tactics, Techniques, and Countermeasures) enrichment step that automatically maps attack steps to known threat intelligence techniques.

## What It Does

After generating attack trees, the wizard offers to:
1. **Extract attack steps** from generated mermaid diagrams
2. **Match steps to techniques** using semantic embeddings (Qwen 0.6B)
3. **Enrich diagrams** with technique IDs (e.g., T1190.A012, AT1029.001)
4. **Add mapping tables** showing technique details and confidence levels

## Usage

### During Wizard Execution

After attack trees are generated, you'll see:

```
🌳 Generated 5 attack trees successfully

🎯 Enrich attack trees with TTC technique mappings? (y/n):
```

**Choose Yes** to enrich attack trees with technique mappings  
**Choose No** to skip enrichment

### What Happens When You Choose Yes

1. **Loads TTC matcher** - Uses pre-generated embeddings (6.6MB)
2. **Processes each attack tree** - Extracts steps and matches to techniques
3. **Creates enriched versions** - Saves to `output/attack_trees/{project}_enriched/`
4. **Shows progress** - Real-time feedback on enrichment status

### Output

**Original attack tree:**
```mermaid
A["Malicious insider"] --> B["Query AWS S3 bucket"]
```

**Enriched attack tree:**
```mermaid
A["Malicious insider<br/><small>T1496.001</small>"] --> B["Query AWS S3 bucket<br/><small>T1190.A012</small>"]
```

**Plus technique mapping table:**
```markdown
## TTC Technique Mappings

| Attack Step | Technique ID | Technique Name | Confidence | Similarity |
|-------------|--------------|----------------|------------|------------|
| Query AWS S3 bucket | T1190.A012 | S3 Bucket | 🟢 high | 0.905 |
```

## Confidence Levels

| Emoji | Level | Similarity | Meaning |
|-------|-------|-----------|---------|
| 🟢 | High | > 0.7 | Excellent match, use directly |
| 🟡 | Medium | 0.5-0.7 | Good match, review recommended |
| 🔴 | Low | 0.35-0.5 | Fair match, manual validation needed |

## File Organization

```
output/
├── attack_trees/
│   ├── {project_name}/
│   │   ├── attack_tree_data_breach.md          # Original
│   │   ├── attack_tree_privilege_escalation.md # Original
│   │   └── ...
│   └── {project_name}_enriched/
│       ├── enriched_attack_tree_data_breach.md          # With TTC mappings
│       ├── enriched_attack_tree_privilege_escalation.md # With TTC mappings
│       └── ...
```

## Performance

- **Speed**: ~0.2 seconds per attack tree
- **Accuracy**: 67% average similarity (71% with AWS term boosting)
- **Model**: Qwen 0.6B (8-13% better than alternatives)
- **Offline**: No API calls after initial setup

## Requirements

The feature requires:
- `sentence-transformers` library
- `scikit-learn` library
- `numpy` library
- Pre-generated embeddings (included in `src/modules/ttc_mappings/data/`)

Install dependencies:
```bash
pip install sentence-transformers scikit-learn numpy
```

## Technical Details

### Matching Approach

1. **Semantic embeddings** - Uses Qwen 0.6B model for understanding
2. **Domain weighting** - Boosts AWS/cloud term matches by 10-20%
3. **Cosine similarity** - Measures semantic similarity between steps and techniques
4. **Confidence thresholds** - Filters matches below 0.35 similarity

### Data Source

- **STIX bundle**: `stix-data/aaf-bundle.json`
- **Techniques**: 229 attack patterns from AWS TTC and MITRE ATT&CK
- **Embeddings**: Pre-generated, 6.6MB file

## Troubleshooting

### "Embeddings file not found"

**Problem**: Missing `src/modules/ttc_mappings/data/ttc_embeddings.json`

**Solution**:
```bash
cd src
python -m modules.ttc_mappings.cli create \
    ../stix-data/aaf-bundle.json \
    -o modules/ttc_mappings/data/ttc_embeddings.json
```

### "Failed to load matcher"

**Problem**: Missing dependencies

**Solution**:
```bash
pip install sentence-transformers scikit-learn numpy
```

### Low similarity scores

**Problem**: All matches have low confidence

**Solutions**:
1. Check if attack steps are descriptive enough
2. Lower threshold: Edit `wizard.py`, change `min_similarity=0.35` to `0.25`
3. Verify embeddings file is correct version

### Enrichment takes too long

**Problem**: Model loading is slow

**Solution**: Model loads once and is reused. First enrichment may take 2-3 seconds for model loading, subsequent enrichments are fast (~0.2s each).

## Manual Enrichment

You can also enrich attack trees manually using the CLI:

```bash
cd src

# Enrich single file
python -m modules.ttc_mappings.cli enrich \
    -e modules/ttc_mappings/data/ttc_embeddings.json \
    -i ../output/attack_trees/myproject/attack_tree_data_breach.md \
    -o ../output/attack_trees/myproject_enriched/

# Enrich directory
python -m modules.ttc_mappings.cli enrich \
    -e modules/ttc_mappings/data/ttc_embeddings.json \
    -i ../output/attack_trees/myproject/ \
    -o ../output/attack_trees/myproject_enriched/
```

## Benefits

✅ **Standardization** - Maps to known threat intelligence frameworks  
✅ **Context** - Adds technique names and descriptions  
✅ **Confidence** - Shows match quality with color-coded levels  
✅ **Fast** - Processes trees in ~0.2s each  
✅ **Offline** - No API costs or rate limits  
✅ **Accurate** - 67-71% average similarity with domain weighting  

## Related Documentation

- **Module README**: `src/modules/ttc_mappings/README.md`
- **Usage Guide**: `src/modules/ttc_mappings/USAGE.md`
- **Test Results**: `embedding-tools/TEST_RESULTS.md`
- **Methodology**: `embedding-tools/MATCHING_ANALYSIS.md`

## Example Session

```
🌳 Generated 3 attack trees successfully

🎯 Enrich attack trees with TTC technique mappings? (y/n): y

🎯 TTC Enrichment
📁 Found 3 attack trees to enrich
🔧 Loading TTC matcher...
✅ TTC matcher loaded
🎯 Enriching 3 attack trees...
✅ Enrichment complete: 3 successful, 0 failed

✅ Enriched 3 attack trees
📁 Enriched files saved to: output/attack_trees/myproject_enriched
```
