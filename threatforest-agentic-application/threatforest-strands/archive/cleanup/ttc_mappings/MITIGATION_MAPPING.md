# Mitigation Mapping Module

Maps MITRE ATT&CK techniques from enriched attack trees to mitigations from the AAF STIX bundle and integrates them directly into attack tree diagrams and tables.

## Overview

This module processes enriched attack tree files (from `output/enriched_v2`) and:
1. Extracts technique IDs (T1234, AT1234) from Mermaid diagrams
2. Looks up mitigations in the STIX bundle (`stix-data/aaf-bundle.json`)
3. **Injects mitigation nodes into Mermaid diagrams** with blue styling
4. **Adds mitigation rows to technique mapping tables**

## Features

### 🎨 Visual Integration
- **Blue mitigation nodes** (🛡️) inserted after attack steps in diagrams
- **Dotted lines** connecting attacks to their mitigations
- **Custom styling**: `fill:#ADD8E6,stroke:#4682B4,stroke-width:2px`

### 📊 Table Integration
- Mitigation rows added directly after related technique rows
- Shows mitigation name, technique ID, and description
- Marked with 🛡️ shield emoji for easy identification

## Usage

### Quick Start (Default Paths)

```bash
cd src/modules/ttc_mappings
python3 map_mitigations.py
```

This processes all files in `output/enriched_v2` and writes to `output/mitigated`.

### Demo with Sample Mitigations

```bash
python3 demo_mitigations.py
```

Creates `output/demo_mitigated.md` with sample mitigations to show the integration.

### Custom Paths

```bash
python3 map_mitigations.py <enriched_dir> [output_dir] [bundle_path]
```

**Examples:**
```bash
# Custom input/output
python3 map_mitigations.py ../../output/enriched_v2 ../../output/my_mitigations

# Custom bundle
python3 map_mitigations.py ../../output/enriched_v2 ../../output/mitigated ../../stix-data/custom-bundle.json
```

### Programmatic Usage

```python
from mitigation_mapper import MitigationMapper

mapper = MitigationMapper('stix-data/aaf-bundle.json')

# Get mitigations for a technique
mitigations = mapper.get_mitigations('T1552')
for m in mitigations:
    print(f"{m['name']}: {m['description']}")

# Process a file
result = mapper.process_enriched_file(
    'output/enriched_v2/attack_tree_T001.md',
    'output/mitigated/attack_tree_T001.md'
)
print(f"Found {len(result['techniques'])} techniques with mitigations")
```

## Output Format

### Mermaid Diagram Integration

**Before:**
```mermaid
A["Attack with credentials<br/><small>T1552</small>"] --> B["Next attack step"]
```

**After:**
```mermaid
A["Attack with credentials<br/><small>T1552</small>"] --> B["Next attack step"]
M1["🛡️ Privileged Account Management"]
A -.-> M1
classDef mitigation fill:#ADD8E6,stroke:#4682B4,stroke-width:2px
class M1 mitigation
```

### Table Integration

**Before:**
```
| Attack Step | Technique ID | Technique Name | Kill Chain Phase | Confidence |
|-------------|--------------|----------------|------------------|------------|
| Attack with credentials | T1552 | Unsecured Credentials | credential-access | 0.490 |
```

**After:**
```
| Attack Step | Technique ID | Technique Name | Kill Chain Phase | Confidence |
|-------------|--------------|----------------|------------------|------------|
| Attack with credentials | T1552 | Unsecured Credentials | credential-access | 0.490 |
| 🛡️ Privileged Account Management | T1552 | Implement MFA, credential vaults... | mitigation | - |
```

## Architecture

### Core Components

- **mitigation_mapper.py**: Core mapping logic
  - `_load_bundle()`: Indexes STIX bundle relationships
  - `_inject_mitigations_into_mermaid()`: Adds mitigation nodes to diagram
  - `_update_technique_table()`: Inserts mitigation rows in table
  - `process_enriched_file()`: Orchestrates the enrichment

- **map_mitigations.py**: CLI wrapper with sensible defaults

- **demo_mitigations.py**: Demo script with sample mitigations

### Processing Flow

```
1. Load STIX bundle → Index technique→mitigation relationships
2. Parse Mermaid diagram → Extract technique IDs from nodes
3. For each technique with mitigations:
   a. Create mitigation node (M1, M2, etc.)
   b. Add dotted line: attack -.-> mitigation
   c. Apply blue styling
4. Parse technique table → Find rows with techniques
5. Insert mitigation rows after technique rows
6. Write enriched content to output file
```

## STIX Bundle Structure

The module expects:
- `attack-pattern` objects with `external_references` containing technique IDs
- `course-of-action` objects (mitigations)
- `relationship` objects with `relationship_type: "mitigates"`

## Performance

- Bundle loaded once at initialization (~486 objects)
- Minimal memory footprint (only indexes technique IDs and mitigation metadata)
- Fast processing (~8 files in <1 second)
- Regex-based diagram and table parsing

## Limitations

- Only processes techniques found in the STIX bundle
- No mitigation = no changes to diagram/table (gracefully handled)
- Extracts techniques from markdown using regex (assumes `<small>T1234</small>` format)
- Mitigation names truncated to 50 chars in diagrams for readability

## Example Output

See `output/demo_mitigated.md` for a complete example with:
- ✅ Blue mitigation nodes in Mermaid diagram
- ✅ Dotted lines connecting attacks to mitigations
- ✅ Mitigation rows in technique table
- ✅ Shield emoji (🛡️) for visual identification

