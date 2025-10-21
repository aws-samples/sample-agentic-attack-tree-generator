# TTC Mappings Module - Summary

## What This Module Does

Matches attack steps to TTC (Tactics, Techniques, Countermeasures) using semantic embeddings with domain-specific weighting for AWS/cloud terms.

## Key Improvements Over Previous Approach

| Aspect | Old (ttc_mapping_tool.py) | New (ttc_mappings module) |
|--------|---------------------------|---------------------------|
| **Method** | Bedrock LLM calls | Embedding-based matching |
| **Speed** | ~2.5s per call + rate limits | ~0.2s for 8 queries |
| **Cost** | API costs per request | One-time model download |
| **Accuracy** | Variable (LLM dependent) | Consistent (0.67 avg similarity) |
| **AWS Boost** | None | +10-20% for AWS queries |
| **Offline** | No (requires API) | Yes (after model download) |

## Module Structure

```
ttc_mappings/
├── __init__.py           # Module exports
├── matcher.py            # Core matching logic
├── enricher.py           # Attack tree enrichment
├── cli.py                # Command-line interface
├── example.py            # Usage examples
├── data/
│   └── ttc_embeddings.json  # Pre-generated embeddings (6.6MB)
├── README.md             # Quick start guide
├── USAGE.md              # Detailed usage guide
└── MODULE_SUMMARY.md     # This file
```

## Quick Usage

### Python API

```python
from modules.ttc_mappings import TTCMatcher, AttackTreeEnricher

# Match attack steps
matcher = TTCMatcher(embeddings_path='modules/ttc_mappings/data/ttc_embeddings.json')
matches = matcher.match_steps(["Query S3 bucket", "Exploit Lambda"])

# Enrich attack trees
enricher = AttackTreeEnricher(matcher)
enricher.enrich_file('input.md', 'output.md')
```

### CLI

```bash
# Match steps
python -m modules.ttc_mappings.cli match \
    -e modules/ttc_mappings/data/ttc_embeddings.json \
    -s "Query S3 bucket"

# Enrich trees
python -m modules.ttc_mappings.cli enrich \
    -e modules/ttc_mappings/data/ttc_embeddings.json \
    -i output/ -o output/enriched/
```

## Features

✅ **Semantic matching** - Understands meaning, not just keywords  
✅ **Domain weighting** - Boosts AWS/cloud term matches  
✅ **Confidence scoring** - High (🟢) / Medium (🟡) / Low (🔴)  
✅ **Attack tree enrichment** - Adds technique IDs to diagrams  
✅ **Fast & offline** - No API calls after setup  
✅ **Pre-generated embeddings** - Ready to use  

## Performance

- **Matching**: 0.2s for 8 queries
- **Accuracy**: 0.67 average similarity (0.71 with domain weighting)
- **AWS queries**: +10-20% similarity boost
- **Model**: Qwen 0.6B (proven 8-13% better than mpnet)

## Confidence Thresholds

| Similarity | Level | Action |
|-----------|-------|--------|
| > 0.7 | 🟢 High | Use directly |
| 0.5-0.7 | 🟡 Medium | Review recommended |
| 0.35-0.5 | 🔴 Low | Manual validation |
| < 0.35 | Filtered | Not returned |

## Integration Points

### Replace Existing Tool

The module can replace `modules/tools/ttc_mapping_tool.py`:

```python
# Old
from modules.tools.ttc_mapping_tool import TTCMappingTool
tool = TTCMappingTool()
result = await tool.execute(attack_trees, aaf_bundle_path, bedrock_model)

# New
from modules.ttc_mappings import TTCMatcher, AttackTreeEnricher
matcher = TTCMatcher(embeddings_path='modules/ttc_mappings/data/ttc_embeddings.json')
enricher = AttackTreeEnricher(matcher)
enriched_trees = [enricher.enrich_attack_tree(tree) for tree in attack_trees]
```

### Use in Pipeline

```python
def enrich_attack_trees_step(attack_trees):
    """Pipeline step to enrich attack trees with TTC mappings"""
    from modules.ttc_mappings import TTCMatcher, AttackTreeEnricher
    
    matcher = TTCMatcher(
        embeddings_path='modules/ttc_mappings/data/ttc_embeddings.json',
        min_similarity=0.35
    )
    enricher = AttackTreeEnricher(matcher)
    
    enriched = []
    for tree in attack_trees:
        enriched_content = enricher.enrich_attack_tree(tree['content'])
        tree['enriched_content'] = enriched_content
        enriched.append(tree)
    
    return enriched
```

## Files Included

1. **matcher.py** (150 lines) - Core matching with domain weighting
2. **enricher.py** (100 lines) - Attack tree enrichment
3. **cli.py** (120 lines) - Command-line interface
4. **example.py** (100 lines) - Usage examples
5. **data/ttc_embeddings.json** (6.6MB) - Pre-generated embeddings
6. **README.md** - Quick start
7. **USAGE.md** - Detailed guide
8. **MODULE_SUMMARY.md** - This file

## Dependencies

```bash
pip install sentence-transformers scikit-learn numpy
```

## Testing

```bash
# Run examples
cd src
python -m modules.ttc_mappings.example

# Test matching
python -c "
from modules.ttc_mappings import TTCMatcher
matcher = TTCMatcher(embeddings_path='modules/ttc_mappings/data/ttc_embeddings.json')
matches = matcher.match_steps(['Query S3 bucket'])
print(matches[0]['matches'][0]['technique_id'])
"
```

## Next Steps

1. ✅ Module created and tested
2. ⏭️ Integrate into main pipeline (replace ttc_mapping_tool.py)
3. ⏭️ Update documentation
4. ⏭️ Add to CI/CD tests

## Support

- **Quick Start**: See `README.md`
- **Detailed Usage**: See `USAGE.md`
- **Methodology**: See `../../embedding-tools/MATCHING_ANALYSIS.md`
- **Test Results**: See `../../embedding-tools/TEST_RESULTS.md`
