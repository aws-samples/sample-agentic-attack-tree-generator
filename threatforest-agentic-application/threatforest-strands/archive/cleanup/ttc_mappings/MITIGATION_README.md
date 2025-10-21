# Mitigation Enrichment Module

Enriches attack trees with defensive mitigations from the AAF STIX bundle.

## Overview

After TTC technique mapping, this module adds mitigation nodes to attack trees by:
1. Finding attack patterns in STIX bundle matching technique IDs
2. Looking up mitigation relationships (`course-of-action` objects)
3. Inserting mitigation nodes after corresponding attack steps
4. Styling mitigations as blue boxes in diagrams

## Usage

### CLI

```bash
# Basic usage
python mitigation_cli.py attack_tree.json

# Specify STIX bundle location
python mitigation_cli.py attack_tree.json --stix-bundle path/to/aaf-bundle.json

# Custom output path
python mitigation_cli.py attack_tree.json --output enriched_tree.json

# Generate Mermaid diagram
python mitigation_cli.py attack_tree.json --mermaid output.mmd
```

### Python API

```python
from mitigation_enricher import MitigationEnricher

# Initialize with STIX bundle
enricher = MitigationEnricher('stix-data/aaf-bundle.json')

# Get mitigations for a technique
mitigations = enricher.get_mitigations_for_technique('T1110.001')

# Enrich attack tree
enriched_tree = enricher.enrich_attack_tree(attack_tree)

# Enrich Mermaid diagram
enriched_mermaid = enricher.enrich_mermaid(mermaid_content, enriched_tree)
```

## Attack Tree Structure

### Input (TTC-enriched)
```json
{
  "nodes": [
    {
      "id": 1,
      "label": "Brute force credentials",
      "technique_id": "T1110.001"
    }
  ]
}
```

### Output (Mitigation-enriched)
```json
{
  "nodes": [
    {
      "id": 1,
      "label": "Brute force credentials",
      "technique_id": "T1110.001"
    },
    {
      "id": 2,
      "label": "🛡️ User Account Management",
      "description": "Manage the creation, modification, use...",
      "type": "mitigation",
      "parent_id": 1,
      "style": "fill:#ADD8E6,stroke:#4682B4,stroke-width:2px"
    }
  ]
}
```

## Mitigation Node Properties

- **label**: Prefixed with 🛡️ emoji
- **type**: Set to `"mitigation"`
- **parent_id**: Links to attack step being mitigated
- **style**: Blue box styling for visual distinction
- **description**: Full mitigation guidance from STIX

## Integration with ThreatForest

Typical workflow:
1. Generate attack tree
2. Enrich with TTC techniques (matcher + enricher)
3. **Add mitigations** (this module)
4. Generate final reports

## No Mitigation Found

If a technique has no mitigation in the STIX bundle, no mitigation node is added. This is expected behavior - not all techniques have documented mitigations.
