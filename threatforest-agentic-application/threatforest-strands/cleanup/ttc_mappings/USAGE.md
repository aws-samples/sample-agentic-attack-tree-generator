# TTC Mappings Module - Usage Guide

## Overview

This module provides semantic matching of attack steps to TTC (Tactics, Techniques, and Countermeasures) using embeddings with domain-specific weighting.

**Key Features:**
- Qwen 0.6B embeddings (8-13% better accuracy than mpnet)
- AWS term boosting (10-20% improvement for cloud queries)
- Confidence scoring (High/Medium/Low)
- Attack tree enrichment with technique IDs

## Installation

The module is already integrated. Required dependencies:

```bash
pip install sentence-transformers scikit-learn numpy
```

## Quick Start

### Python API

```python
from modules.ttc_mappings import TTCMatcher, AttackTreeEnricher
from pathlib import Path

# Initialize matcher with pre-generated embeddings
embeddings_path = 'modules/ttc_mappings/data/ttc_embeddings.json'
matcher = TTCMatcher(embeddings_path=embeddings_path, min_similarity=0.35)

# Match attack steps
steps = ["Query AWS S3 bucket", "Exploit Lambda function"]
matches = matcher.match_steps(steps, top_k=3)

# Print results
for match in matches:
    print(f"{match['attack_step']}")
    for m in match['matches']:
        print(f"  → {m['technique_id']} ({m['similarity']:.3f})")
```

### CLI

```bash
# Match attack steps
python -m modules.ttc_mappings.cli match \
    -e modules/ttc_mappings/data/ttc_embeddings.json \
    -s "Query S3 bucket" "Exploit Lambda" \
    --min-similarity 0.35

# Enrich attack trees
python -m modules.ttc_mappings.cli enrich \
    -e modules/ttc_mappings/data/ttc_embeddings.json \
    -i output/ \
    -o output/enriched/
```

## Detailed Usage

### 1. Matching Attack Steps

```python
from modules.ttc_mappings import TTCMatcher

# Initialize
matcher = TTCMatcher(
    embeddings_path='modules/ttc_mappings/data/ttc_embeddings.json',
    model_name='Qwen/Qwen3-Embedding-0.6B',  # Default
    min_similarity=0.35  # Confidence threshold
)

# Match steps
attack_steps = [
    "Query AWS S3 bucket for sensitive data",
    "Exploit Lambda function vulnerability",
    "Access DynamoDB table without authorization"
]

matches = matcher.match_steps(attack_steps, top_k=3)

# Process results
for match in matches:
    step = match['attack_step']
    best_match = match['matches'][0]
    
    print(f"Step: {step}")
    print(f"  Technique: {best_match['technique_id']}")
    print(f"  Name: {best_match['name']}")
    print(f"  Confidence: {best_match['confidence']}")
    print(f"  Similarity: {best_match['similarity']:.3f}")
```

### 2. Enriching Attack Trees

```python
from modules.ttc_mappings import TTCMatcher, AttackTreeEnricher

# Initialize
matcher = TTCMatcher(embeddings_path='modules/ttc_mappings/data/ttc_embeddings.json')
enricher = AttackTreeEnricher(matcher)

# Enrich single file
enricher.enrich_file(
    input_path='output/attack_tree_T001.md',
    output_path='output/enriched_attack_tree_T001.md'
)

# Enrich directory
enricher.enrich_directory(
    input_dir='output/',
    output_dir='output/enriched/',
    pattern='attack_tree_*.md'
)
```

### 3. Creating New Embeddings

If you need to regenerate embeddings from updated STIX data:

```python
from modules.ttc_mappings import TTCMatcher

matcher = TTCMatcher(model_name='Qwen/Qwen3-Embedding-0.6B')

embeddings_data = matcher.create_embeddings(
    stix_bundle_path='stix-data/aaf-bundle.json',
    output_path='modules/ttc_mappings/data/ttc_embeddings.json'
)

print(f"Created {len(embeddings_data['patterns'])} embeddings")
```

## Integration with Existing Tools

### Replace ttc_mapping_tool.py

The new module can replace the existing `ttc_mapping_tool.py`:

```python
# Old approach (Bedrock-based)
from modules.tools.ttc_mapping_tool import TTCMappingTool

# New approach (Embedding-based)
from modules.ttc_mappings import TTCMatcher, AttackTreeEnricher

# Initialize
matcher = TTCMatcher(embeddings_path='modules/ttc_mappings/data/ttc_embeddings.json')
enricher = AttackTreeEnricher(matcher)

# Use in pipeline
def process_attack_trees(attack_trees):
    for tree in attack_trees:
        enriched = enricher.enrich_attack_tree(tree['content'])
        tree['enriched_content'] = enriched
    return attack_trees
```

## Output Examples

### Match Results

```json
{
  "attack_step": "Query AWS S3 bucket for sensitive data",
  "matches": [
    {
      "technique_id": "T1190.A012",
      "name": "S3 Bucket",
      "description": "Adversaries may attempt to access...",
      "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
      "similarity": 0.912,
      "confidence": "high"
    }
  ]
}
```

### Enriched Mermaid Diagram

**Before:**
```mermaid
A["Malicious insider"] --> B["Query S3 bucket"]
```

**After:**
```mermaid
A["Malicious insider<br/><small>T1552</small>"] --> B["Query S3 bucket<br/><small>T1190.A012</small>"]
```

**With Technique Table:**
```markdown
## TTC Technique Mappings

| Attack Step | Technique ID | Technique Name | Confidence | Similarity |
|-------------|--------------|----------------|------------|------------|
| Query S3 bucket | T1190.A012 | S3 Bucket | 🟢 high | 0.912 |
```

## Confidence Levels

| Level | Similarity | Emoji | Recommendation |
|-------|-----------|-------|----------------|
| **High** | > 0.7 | 🟢 | Use directly, excellent match |
| **Medium** | 0.5-0.7 | 🟡 | Good match, review recommended |
| **Low** | 0.35-0.5 | 🔴 | Fair match, manual validation needed |
| **Filtered** | < 0.35 | - | Below threshold, not returned |

## Performance

- **Model loading**: ~2 seconds (lazy loaded)
- **Embedding creation**: ~10 seconds for 229 techniques
- **Matching**: ~0.2 seconds for 8 queries
- **Domain weighting**: No performance penalty (faster than baseline)

## Configuration

### Similarity Threshold

Adjust based on your needs:

```python
# Strict (only high confidence)
matcher = TTCMatcher(min_similarity=0.7)

# Balanced (recommended)
matcher = TTCMatcher(min_similarity=0.35)

# Permissive (include more matches)
matcher = TTCMatcher(min_similarity=0.2)
```

### Model Selection

```python
# Recommended (best balance)
matcher = TTCMatcher(model_name='Qwen/Qwen3-Embedding-0.6B')

# Alternative (if Qwen unavailable)
matcher = TTCMatcher(model_name='sentence-transformers/all-mpnet-base-v2')
```

## Troubleshooting

### Model Download Issues

If the model fails to download:

```python
# Pre-download the model
from sentence_transformers import SentenceTransformer
model = SentenceTransformer('Qwen/Qwen3-Embedding-0.6B')
```

### Low Similarity Scores

If all matches have low similarity:
1. Check if attack steps are descriptive enough
2. Lower the `min_similarity` threshold
3. Verify embeddings are loaded correctly

### Missing Embeddings File

If embeddings file is missing:

```bash
# Regenerate from STIX data
python -m modules.ttc_mappings.cli create \
    stix-data/aaf-bundle.json \
    -o modules/ttc_mappings/data/ttc_embeddings.json
```

## Testing

Run the example script:

```bash
cd src
python -m modules.ttc_mappings.example
```

## Further Reading

- `README.md` - Module overview
- `../../embedding-tools/MATCHING_ANALYSIS.md` - Detailed methodology
- `../../embedding-tools/TEST_RESULTS.md` - Performance benchmarks
