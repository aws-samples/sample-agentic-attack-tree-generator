# ThreatForest Embedding Tools

CLI tools for matching attack tree steps to MITRE ATT&CK and Amazon-specific techniques using semantic embeddings.

## Files

- `cli.py` - **Main CLI tool** 🔧
- `create_embeddings.py` - Generate embeddings from STIX attack patterns
- `match_attack_steps.py` - Match attack tree steps to techniques
- `load_matches.py` - Load and filter matching results
- `attack_pattern_embeddings.json` - Pre-generated embeddings (229 techniques)
- `attack_step_matches.json` - Attack step to technique mappings

## CLI Usage

### 🔧 Main Commands

```bash
# Show help
python cli.py --help

# Create embeddings from STIX data
python cli.py create

# Match attack steps to techniques
python cli.py match

# Show technique matches
python cli.py show

# List available techniques
python cli.py list

# Find techniques similar to query
python cli.py find "steal credentials"

# Enrich attack trees with technique data
python cli.py enrich
```

### 📋 Show Matches

```bash
# Show all matches
python cli.py show

# Filter by file and similarity
python cli.py show --file data_breach --min-similarity 0.4

# Show top 3 matches per step
python cli.py show --top 3
```

### 🔍 Search Techniques

```bash
# List all techniques
python cli.py list

# Search for AWS techniques
python cli.py list --search "AWS"

# Find similar techniques
python cli.py find "compromise container" --top 5
```

### 🎯 Enrich Attack Trees

```bash
# Enrich with default settings (similarity >= 0.3)
python cli.py enrich

# Higher confidence threshold
python cli.py enrich --min-similarity 0.4

# Custom output directory
python cli.py enrich --output-dir ../output/my_enriched

# Process single file
python cli.py enrich --input ../output/attack_tree_T001_data_breach.md

# Process custom directory
python cli.py enrich --input /path/to/attack/trees/
```

### 📁 Input Path Options

**Match and Enrich commands support flexible input:**

```bash
# Default: Process ../output/attack_tree_*.md
python cli.py match
python cli.py enrich

# Single file
python cli.py match --input ../output/attack_tree_T001_data_breach.md
python cli.py enrich --input /path/to/single_tree.md

# Directory (processes all .md files)
python cli.py match --input /path/to/attack/trees/
python cli.py enrich --input ../custom_trees/

# Different input and output
python cli.py enrich --input /source/trees/ --output-dir /enriched/trees/
```

**What `enrich` does:**
- **Updates mermaid diagrams** with technique IDs in attack step nodes
- **Adds technique mapping table** with full details
- **Preserves original files** (saves to separate directory)
- **Filters by confidence** using similarity threshold

**Example enriched mermaid:**
```mermaid
A["Malicious insider<br/><small>T1552</small>"] --> B["SFTP reconnaissance<br/><small>AT1019</small>"]
```

## Quick Start

### 1. Generate Embeddings (if needed)
```bash
python cli.py create
```

### 2. Match Attack Steps
```bash
python cli.py match
```

### 3. Enrich Attack Trees
```bash
# Creates enriched files with technique IDs in diagrams
python cli.py enrich --min-similarity 0.4
```

### 4. View Results
```bash
# Show high-confidence matches
python cli.py show --min-similarity 0.4

# Find techniques for specific attack
python cli.py find "lateral movement"
```

## Legacy Python API

```python
from load_matches import load_matches, get_matches_for_file

# Load all matches
matches = load_matches()

# Get high-confidence matches (>30% similarity)
good_matches = get_matches_for_file(matches, 'attack_tree_T001_data_breach.md', min_similarity=0.3)

# Print results
for match in good_matches:
    step = match['attack_step']
    technique = match['matches'][0]
    print(f"{step} → {technique['technique_id']} ({technique['similarity']:.3f})")
```

## Model Used

**sentence-transformers/all-mpnet-base-v2**
- 768-dimensional embeddings
- High accuracy for technical security text
- Good at distinguishing similar attack techniques

## Output Format

### Enriched Attack Trees
- **Mermaid diagrams**: Attack steps show technique IDs as small tags
- **Technique table**: Complete mapping with kill chain phases and confidence
- **Preserved structure**: Original content maintained with additions

### JSON Matches
```json
{
  "attack_tree_T001_data_breach.md": [
    {
      "attack_step": "Authenticate to AWS Transfer SFTP endpoint",
      "matches": [
        {
          "technique_id": "T1078.A003",
          "name": "Console Login",
          "description": "Adversaries may access...",
          "similarity": 0.497
        }
      ]
    }
  ]
}
```

## Requirements

```bash
pip install sentence-transformers scikit-learn numpy
```

## Usage Tips

- **Similarity > 0.5**: Excellent match
- **Similarity > 0.3**: Good match  
- **Similarity < 0.3**: Review manually

Use `--min-similarity` to filter results by confidence level.
