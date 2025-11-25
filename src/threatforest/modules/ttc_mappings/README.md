# TTC Mappings Module

Semantic matching of attack steps to TTC techniques using embeddings with domain weighting.

## Features

- **Qwen 0.6B embeddings** - 8-13% better than mpnet
- **Domain weighting** - 10-20% boost for AWS-specific queries
- **Confidence levels** - High/Medium/Low based on similarity
- **Attack tree enrichment** - Add technique IDs to mermaid diagrams

## Quick Start

### 1. Create Embeddings

```python
from modules.ttc_mappings import TTCMatcher

matcher = TTCMatcher(model_name='Qwen/Qwen3-Embedding-0.6B')
matcher.create_embeddings(
    stix_bundle_path='stix-data/aaf-bundle.json',
    output_path='embeddings/ttc_embeddings.json'
)
```

### 2. Match Attack Steps

```python
steps = [
    "Query AWS S3 bucket for sensitive data",
    "Exploit Lambda function vulnerability"
]

matches = matcher.match_steps(steps, top_k=3)

for match in matches:
    print(f"{match['attack_step']}")
    for m in match['matches']:
        print(f"  → {m['technique_id']} ({m['similarity']:.3f})")
```

### 3. Enrich Attack Trees

```python
from modules.ttc_mappings import AttackTreeEnricher

enricher = AttackTreeEnricher(matcher)
enricher.enrich_file(
    'output/attack_tree_T001.md',
    'output/enriched_attack_tree_T001.md'
)
```

## CLI Usage

### Create Embeddings
```bash
python -m modules.ttc_mappings.cli create \
    stix-data/aaf-bundle.json \
    -o embeddings/ttc_embeddings.json
```

### Match Steps
```bash
python -m modules.ttc_mappings.cli match \
    -e embeddings/ttc_embeddings.json \
    -s "Query S3 bucket" "Exploit Lambda" \
    --min-similarity 0.35
```

### Enrich Attack Trees
```bash
python -m modules.ttc_mappings.cli enrich \
    -e embeddings/ttc_embeddings.json \
    -i output/ \
    -o output/enriched/ \
    --min-similarity 0.35
```

## API Reference

### TTCMatcher

```python
matcher = TTCMatcher(
    embeddings_path='path/to/embeddings.json',  # Optional
    model_name='Qwen/Qwen3-Embedding-0.6B',     # Default
    min_similarity=0.35                          # Default
)

# Create embeddings
matcher.create_embeddings(stix_bundle_path, output_path)

# Match steps
matches = matcher.match_steps(attack_steps, top_k=3)
```

### AttackTreeEnricher

```python
enricher = AttackTreeEnricher(matcher)

# Enrich single file
enricher.enrich_file(input_path, output_path)

# Enrich directory
enricher.enrich_directory(input_dir, output_dir, pattern='*.md')
```

## Confidence Levels

| Level | Similarity | Emoji | Action |
|-------|-----------|-------|--------|
| High | > 0.7 | 🟢 | Use directly |
| Medium | 0.5-0.7 | 🟡 | Review recommended |
| Low | 0.35-0.5 | 🔴 | Manual validation |

## Output Format

### Match Results
```json
{
  "attack_step": "Query AWS S3 bucket",
  "matches": [
    {
      "technique_id": "T1190.A012",
      "name": "S3 Bucket",
      "description": "...",
      "similarity": 0.912,
      "confidence": "high",
      "kill_chain_phases": [...]
    }
  ]
}
```

### Enriched Mermaid
```mermaid
A["Malicious insider<br/><small>T1552</small>"] --> B["Query S3 bucket<br/><small>T1190.A012</small>"]
```

## Requirements

```bash
pip install sentence-transformers scikit-learn numpy
```

## Performance

- **Model loading**: ~2s
- **Embedding creation**: ~10s for 229 techniques
- **Matching**: ~0.2s for 8 queries
- **Domain weighting**: No performance penalty

## Testing

See `../../embedding-tools/TEST_RESULTS.md` for detailed test results and validation.
